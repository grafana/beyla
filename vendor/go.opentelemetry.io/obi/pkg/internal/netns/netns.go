// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netns // import "go.opentelemetry.io/obi/pkg/internal/netns"

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// thread-self, not self: the namespace being saved and restored is the locked thread's
const selfNetNS = "/proc/thread-self/ns/net"

func netNSPath(hostPid int) string {
	return fmt.Sprintf("/proc/%d/ns/net", hostPid)
}

// statNetNSInode is injectable for tests.
var statNetNSInode = netNSInode

// IsIsolated reports whether pid's network namespace is distinct from both the
// calling process and PID 1. Isolated namespaces are Docker/containerd bridge
// nets; host-network and bare-host processes share the agent or host netns.
func IsIsolated(pid int) (bool, error) {
	pidIno, err := statNetNSInode(netNSPath(pid))
	if err != nil {
		return false, fmt.Errorf("stat pid netns: %w", err)
	}

	selfIno, err := statNetNSInode(netNSPath(os.Getpid()))
	if err != nil {
		return false, fmt.Errorf("stat self netns: %w", err)
	}

	if pidIno == selfIno {
		return false, nil
	}

	hostIno, err := statNetNSInode(netNSPath(1))
	if err != nil {
		return false, fmt.Errorf("stat host netns: %w", err)
	}

	return pidIno != hostIno, nil
}

func netNSInode(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// WithNetNS runs fn in the network namespace of hostPid.
//
// The switch runs on a goroutine of its own, and that goroutine returns while still locked
// whenever the namespace cannot be restored. The runtime then terminates the thread instead
// of returning it to the pool, so a failed restore can neither strand the caller in the
// wrong namespace nor hand a tainted thread to an unrelated goroutine.
//
// fn runs on that goroutine, so a panic inside it takes the process down rather than
// unwinding into the caller. It must not call runtime.UnlockOSThread: that would release the
// pin and let the scheduler hand the thread on while it is still in the target namespace.
//
// Only things that resolve the namespace when they are used see the switch. Sockets and BPF
// iterators do; an already-mounted /sys does not, and keeps the view of whichever namespace
// mounted it.
func WithNetNS(hostPid int, fn func() error) error {
	target := netNSPath(hostPid)
	done := make(chan error, 1)

	go func() {
		// lock before comparing: the comparison is against this thread's namespace, and a
		// goroutine can otherwise migrate between threads while fn runs
		runtime.LockOSThread()

		same, err := sameNetNS(target)
		if err != nil {
			runtime.UnlockOSThread()
			done <- err
			return
		}
		if same {
			fnErr := fn()
			runtime.UnlockOSThread()
			done <- fnErr
			return
		}

		selfNS, err := os.Open(selfNetNS)
		if err != nil {
			runtime.UnlockOSThread()
			done <- fmt.Errorf("open self netns: %w", err)
			return
		}

		defer selfNS.Close()

		targetNS, err := os.Open(target)
		if err != nil {
			runtime.UnlockOSThread()
			done <- fmt.Errorf("open target netns: %w", err)
			return
		}

		defer targetNS.Close()

		if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
			runtime.UnlockOSThread()
			done <- fmt.Errorf("join target netns: %w", err)
			return
		}

		fnErr := fn()

		if err := unix.Setns(int(selfNS.Fd()), unix.CLONE_NEWNET); err != nil {
			done <- errors.Join(fnErr, fmt.Errorf("restore netns: %w", err))
			return
		}

		runtime.UnlockOSThread()
		done <- fnErr
	}()

	return <-done
}

func sameNetNS(target string) (bool, error) {
	self, err := os.Readlink(selfNetNS)
	if err != nil {
		return false, fmt.Errorf("read self netns: %w", err)
	}

	other, err := os.Readlink(target)
	if err != nil {
		return false, fmt.Errorf("read target netns: %w", err)
	}

	return self == other, nil
}
