// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"go.opentelemetry.io/obi/pkg/internal/jvmtools/util"
)

type JAttacher struct {
	logger     *slog.Logger
	j9attacher *j9Attacher
	myUID      int
	myGID      int
	myPID      int
}

func NewJAttacher(logger *slog.Logger) *JAttacher {
	if logger == nil {
		logger = slog.Default()
	}

	return &JAttacher{
		logger:     logger,
		j9attacher: nil,
	}
}

func (j *JAttacher) Init() {
	myUID := syscall.Geteuid()
	myGID := syscall.Getegid()
	myPID := os.Getpid()

	j.myUID = myUID
	j.myGID = myGID
	j.myPID = myPID
}

func (j *JAttacher) Cleanup() error {
	var cleanupErr error

	if j.j9attacher != nil {
		cleanupErr = errors.Join(cleanupErr, j.j9attacher.detach())
	}
	if err := syscall.Seteuid(j.myUID); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}
	if err := syscall.Setegid(j.myGID); err != nil {
		cleanupErr = errors.Join(cleanupErr, err)
	}

	for _, nsType := range []string{"net", "ipc", "mnt"} {
		if util.EnterNS(j.myPID, nsType) < 0 {
			err := fmt.Errorf("failed to restore %s namespace", nsType)
			cleanupErr = errors.Join(cleanupErr, err)
		}
	}

	return cleanupErr
}

func (j *JAttacher) Attach(pid int, argv []string, ignoreOnJ9 bool) (io.ReadCloser, error) {
	targetUID := j.myUID
	targetGID := j.myGID
	var nspid int

	if err := util.GetProcessInfo(pid, &targetUID, &targetGID, &nspid); err != nil {
		return nil, fmt.Errorf("process not found: %d: %w", pid, err)
	}

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
	if (j.myGID != targetGID && syscall.Setegid(targetGID) != nil) ||
		(j.myUID != targetUID && syscall.Seteuid(targetUID) != nil) {
		return nil, errors.New("failed to change credentials to match the target process")
	}

	attachPid := pid
	if mntChanged > 0 {
		attachPid = nspid
	}

	tmpPath := util.GetTmpPath(attachPid)

	// Make write() return EPIPE instead of abnormal process termination
	signal.Ignore(syscall.SIGPIPE)

	if isOpenJ9Process(tmpPath, attachPid) {
		if ignoreOnJ9 {
			return nil, nil
		}
		j9attacher := newJ9Attacher(j.logger)
		j.j9attacher = j9attacher
		return j.j9attacher.jattachOpenJ9(tmpPath, nspid, argv)
	}

	return jattachHotspot(pid, nspid, attachPid, argv, tmpPath, j.logger)
}
