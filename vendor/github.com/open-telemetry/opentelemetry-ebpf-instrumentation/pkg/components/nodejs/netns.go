//go:build linux

package nodejs

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// withNetNS locks the goroutine to an OS thread, switches that thread’s
// network namespace to the one belonging to `hostPid`, runs fn(), and
// then switches back to the original namespace.
func withNetNS(hostPid int, fn func() error) error {
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
			// FIXME log instead
			panic(fmt.Sprintf("failed to restore netns: %v", err))
		}
	}()

	return fn()
}
