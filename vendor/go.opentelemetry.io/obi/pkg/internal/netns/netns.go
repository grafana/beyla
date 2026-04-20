// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netns // import "go.opentelemetry.io/obi/pkg/internal/netns"

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// WithNetNS locks the goroutine to an OS thread, switches that thread's
// network namespace to the one belonging to hostPid, runs fn(), and
// then switches back to the original namespace.
func WithNetNS(hostPid int, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	selfNS, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return fmt.Errorf("open self netns: %w", err)
	}

	defer selfNS.Close()

	targetNS, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", hostPid))
	if err != nil {
		return fmt.Errorf("open target netns: %w", err)
	}

	defer targetNS.Close()

	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("join target ns: %w", err)
	}

	defer func() {
		if err := unix.Setns(int(selfNS.Fd()), unix.CLONE_NEWNET); err != nil {
			panic(fmt.Sprintf("failed to restore netns: %v", err))
		}
	}()

	return fn()
}
