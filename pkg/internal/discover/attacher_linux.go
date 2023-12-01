package discover

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func (ta *TraceAttacher) close() {
	ta.unmountBpfPinPath()
}

func (ta *TraceAttacher) mountBpfPinPath() error {
	ta.log.Debug("mounting BPF map pinning", "path", ta.pinPath)
	if _, err := os.Stat(ta.pinPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("accessing %s stat: %w", ta.pinPath, err)
		}
		ta.log.Debug("BPF map pinning path does not exist. Creating before mounting")
		if err := os.MkdirAll(ta.pinPath, 0700); err != nil {
			return fmt.Errorf("creating directory %s: %w", ta.pinPath, err)
		}
	}

	return bpfMount(ta.pinPath)
}

func (ta *TraceAttacher) unmountBpfPinPath() {
	if err := unix.Unmount(ta.pinPath, unix.MNT_FORCE); err != nil {
		ta.log.Warn("can't unmount pinned root. Try unmounting and removing it manually", err)
		return
	}
	ta.log.Debug("unmounted bpf file system")
	if err := os.RemoveAll(ta.pinPath); err != nil {
		ta.log.Warn("can't remove pinned root. Try removing it manually", err)
	} else {
		ta.log.Debug("removed pin path")
	}
}

func bpfMount(pinPath string) error {
	return unix.Mount(pinPath, pinPath, "bpf", 0, "")
}

func (ta *TraceAttacher) init() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	if err := ta.mountBpfPinPath(); err != nil {
		return fmt.Errorf("can't mount BPF filesystem: %w", err)
	}
	return nil
}
