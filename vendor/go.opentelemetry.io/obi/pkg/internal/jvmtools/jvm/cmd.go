// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"

	"go.opentelemetry.io/obi/pkg/internal/jvmtools/util"
)

// extracted for testing
var (
	getEUID = syscall.Geteuid
	getEGID = syscall.Getegid
	setEUID = syscall.Seteuid
	setEGID = syscall.Setegid
)

var errTerminated = errors.New("attach terminated")

type JAttacher struct {
	logger             *slog.Logger
	j9attacher         *j9Attacher
	myUID              int
	myGID              int
	mu                 sync.Mutex
	initialized        bool
	terminated         bool
	attachID           int64
	runIfCurrentAttach func(int64, func() error) error
}

func NewJAttacher(logger *slog.Logger, attachID int64, runIfCurrentAttach func(int64, func() error) error) *JAttacher {
	if logger == nil {
		logger = slog.Default()
	}

	return &JAttacher{
		logger:             logger,
		j9attacher:         nil,
		attachID:           attachID,
		runIfCurrentAttach: runIfCurrentAttach,
	}
}

func (j *JAttacher) setEUID(euid int) (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.terminated && euid != j.myUID {
		return errTerminated
	}
	return setEUID(euid)
}

func (j *JAttacher) setEGID(egid int) (err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.terminated && egid != j.myGID {
		return errTerminated
	}
	return setEGID(egid)
}

func (j *JAttacher) Init() {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.initialized {
		return
	}

	j.myUID = getEUID()
	j.myGID = getEGID()
	j.initialized = true
}

func (j *JAttacher) restoreCredentialsLocked() error {
	var restoreErr error
	// Credentials (euid/egid) are switched process-wide during Attach, so they
	// must be restored here. Namespaces are NOT restored: the namespace switch
	// happens only on the dedicated sacrificial thread spawned by Attach, which
	// is destroyed once attach completes — the runtime's pool threads never
	// leave their original namespaces, so there is nothing to roll back.
	if err := setEUID(j.myUID); err != nil {
		restoreErr = errors.Join(restoreErr, err)
	}
	if err := setEGID(j.myGID); err != nil {
		restoreErr = errors.Join(restoreErr, err)
	}

	// No need to restore the pid namespace, since we do this on a
	// locked thread that's never unlocked, which means the Go runtime
	// will destroy it when the goroutine ends.

	return restoreErr
}

func (j *JAttacher) Terminate() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.terminated = true

	if !j.initialized {
		return nil
	}

	return j.restoreCredentialsLocked()
}

func (j *JAttacher) Cleanup() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if !j.initialized {
		return nil
	}

	var cleanupErr error

	if j.j9attacher != nil {
		cleanupErr = errors.Join(cleanupErr, j.j9attacher.detach())
	}

	// Restore credentials if we are the active attach happening on the pipeline.
	// If we were delayed and the main loop abandoned us, they would reset the
	// credentials in Terminate and they might be in process of other JVM attach.
	cleanupErr = errors.Join(
		cleanupErr,
		j.runIfCurrentAttach(
			j.attachID,
			j.restoreCredentialsLocked,
		),
	)

	return cleanupErr
}

func (j *JAttacher) Attach(ctx context.Context, pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	targetUID := j.myUID
	targetGID := j.myGID
	var nspid int

	// Resolve the target's credentials and in-namespace PID from the host
	// namespace, before we move anywhere.
	if err := util.GetProcessInfo(pid, &targetUID, &targetGID, &nspid); err != nil {
		return nil, fmt.Errorf("process not found: %d: %w", pid, err)
	}

	// Entering the target's mount namespace requires setns(CLONE_NEWNS), which
	// the kernel refuses for any thread that shares filesystem attributes with
	// the rest of the Go runtime's thread pool (see util.EnterNS). We therefore
	// run the entire namespace-sensitive attach sequence on a dedicated OS
	// thread that is locked and never unlocked: when this goroutine returns,
	// the runtime destroys the thread instead of recycling one that is stranded
	// in the target's namespaces with an unshared, private filesystem context.
	//
	// The attach result is an fd-backed io.ReadCloser (a unix socket conn for
	// HotSpot, or a raw fd reader for OpenJ9). Once established, that fd belongs
	// to the process and can be read from any thread, so the caller is free to
	// consume it after this sacrificial thread is gone.
	type attachResult struct {
		reader io.ReadCloser
		err    error
	}
	resultCh := make(chan attachResult, 1)

	go func() {
		// This goroutine runs independently of the caller's goroutine, so a
		// panic here would escape the callers' own recover take down the whole process.
		// Convert it into an attach error instead.
		defer func() {
			if r := recover(); r != nil {
				j.logger.Error("recovered from panic during JVM attach",
					"pid", pid, "panic", r, "stack", string(debug.Stack()))
				resultCh <- attachResult{err: fmt.Errorf("panic during JVM attach: %v", r)}
			}
		}()

		runtime.LockOSThread()
		// Deliberately no runtime.UnlockOSThread: this thread is tainted by the
		// namespace switch and CLONE_FS unshare, so we let it die with the
		// goroutine rather than return it to the pool.
		reader, err := j.attachInNamespace(ctx, pid, nspid, targetUID, targetGID, argv, ignoreOnJ9)
		resultCh <- attachResult{reader: reader, err: err}
	}()

	res := <-resultCh
	return res.reader, res.err
}

// attachInNamespace performs the namespace switch, credential change and JVM
// handshake. It MUST be called from a goroutine pinned to a dedicated,
// never-unlocked OS thread (see Attach), because it both joins the target's
// mount namespace and unshares CLONE_FS on the calling thread.
func (j *JAttacher) attachInNamespace(ctx context.Context, pid, nspid, targetUID, targetGID int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	// Container support: switch to the target namespaces.
	// Network and IPC namespaces are essential for OpenJ9 connection.
	if util.EnterNS(pid, "net") < 0 {
		return nil, errors.New("failed to enter target net namespace")
	}
	if util.EnterNS(pid, "ipc") < 0 {
		return nil, errors.New("failed to enter target ipc namespace")
	}
	mntChanged := util.EnterNS(pid, "mnt")
	if mntChanged < 0 {
		return nil, errors.New("failed to enter target mnt namespace")
	}

	// In HotSpot, dynamic attach is allowed only for the clients with the same euid/egid.
	// If we are running under root, switch to the required euid/egid automatically.
	// We must use j.setEGID and j.setEUID instead of setEUID and setEGID to ensure OBI
	// is still waiting on the attach, rather than changing the user credentials after OBI
	// has abandoned this attach in the pipeline.
	if (j.myGID != targetGID && j.setEGID(targetGID) != nil) ||
		(j.myUID != targetUID && j.setEUID(targetUID) != nil) {
		return nil, errors.New("failed to change credentials to match the target process")
	}

	attachPid := pid
	if mntChanged > 0 {
		attachPid = nspid
	}

	tmpPath := util.GetTmpPath(attachPid)

	// Make write() return EPIPE instead of abnormal process termination
	signal.Ignore(syscall.SIGPIPE)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if isOpenJ9Process(tmpPath, attachPid) {
		if ignoreOnJ9 {
			return nil, nil
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		j9attacher := newJ9Attacher(j.logger)
		j.j9attacher = j9attacher
		return j.j9attacher.jattachOpenJ9(tmpPath, nspid, argv)
	}

	return jattachHotspot(ctx, pid, nspid, attachPid, argv, tmpPath, j.logger)
}
