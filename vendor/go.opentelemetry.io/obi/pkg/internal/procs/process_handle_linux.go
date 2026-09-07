// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

var (
	pidfdSendSignal = unix.PidfdSendSignal
	procRootPath    = "/proc"
)

// ProcessHandle is a stable reference to one process incarnation. The proc
// directory descriptor is also a pidfd on supported kernels, and all proc
// resources are opened relative to it so a recycled numeric PID is never used.
type ProcessHandle struct {
	pid      app.PID
	procDir  *os.File
	close    sync.Once
	closeErr error
}

// OpenProcessHandle opens the process seen during inspection and validates its
// start time before returning it. Stable signaling is checked up front so
// callers never fall back to signaling a numeric PID.
func OpenProcessHandle(pid app.PID, expectedStartTime uint64) (*ProcessHandle, error) {
	if expectedStartTime == 0 {
		return nil, fmt.Errorf("identity of process %d was not captured", pid)
	}

	path := filepath.Join(procRootPath, strconv.Itoa(int(pid)))
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening process %d: %w", pid, err)
	}

	handle := &ProcessHandle{
		pid:     pid,
		procDir: os.NewFile(uintptr(fd), path),
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = handle.Close()
		}
	}()

	actualStartTime, err := handle.startTime()
	if err != nil {
		return nil, fmt.Errorf("confirming identity of process %d: %w", pid, err)
	}
	if actualStartTime != expectedStartTime {
		return nil, fmt.Errorf("process %d was replaced before injection", pid)
	}
	if err := handle.Alive(); err != nil {
		return nil, fmt.Errorf("opening stable reference to process %d: %w", pid, err)
	}

	cleanup = false
	return handle, nil
}

func (p *ProcessHandle) PID() app.PID {
	return p.pid
}

// Open opens a proc resource relative to the stable process directory.
func (p *ProcessHandle) Open(name string, flags int) (*os.File, error) {
	if p == nil || p.procDir == nil {
		return nil, errors.New("process handle is unavailable")
	}

	fd, err := unix.Openat(int(p.procDir.Fd()), name, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(fd), name), nil
}

// Alive verifies that the referenced process still exists. An unsupported
// pidfd_send_signal syscall is an error because numeric-PID signaling is not a
// safe fallback.
func (p *ProcessHandle) Alive() error {
	if p == nil || p.procDir == nil {
		return errors.New("process handle is unavailable")
	}

	return pidfdSendSignal(int(p.procDir.Fd()), 0, nil, 0)
}

func (p *ProcessHandle) SendSignal(signal unix.Signal) error {
	if p == nil || p.procDir == nil {
		return errors.New("process handle is unavailable")
	}

	return pidfdSendSignal(int(p.procDir.Fd()), signal, nil, 0)
}

func (p *ProcessHandle) Close() error {
	if p == nil {
		return nil
	}

	p.close.Do(func() {
		if p.procDir != nil {
			p.closeErr = p.procDir.Close()
		}
	})
	return p.closeErr
}

func (p *ProcessHandle) startTime() (uint64, error) {
	stat, err := p.Open("stat", unix.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer stat.Close()

	data, err := io.ReadAll(stat)
	if err != nil {
		return 0, err
	}

	return parseStartTime(data)
}

func parseStartTime(stat []byte) (uint64, error) {
	commEnd := strings.LastIndex(string(stat), ") ")
	if commEnd < 0 {
		return 0, errors.New("invalid process stat")
	}

	// The fields after comm begin at field 3 (state); starttime is field 22.
	fields := strings.Fields(string(stat[commEnd+2:]))
	const startTimeIndex = 22 - 3
	if len(fields) <= startTimeIndex {
		return 0, errors.New("process stat has no start time")
	}

	startTime, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing process start time: %w", err)
	}
	return startTime, nil
}
