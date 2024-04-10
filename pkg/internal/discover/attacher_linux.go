package discover

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

	return ta.bpfMount(ta.pinPath)
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

func (ta *TraceAttacher) bpfMount(pinPath string) error {
	mounted, bpffsInstance, err := isBPFMountFS(pinPath)
	if err != nil {
		return err
	}
	if !mounted {
		return unix.Mount(pinPath, pinPath, "bpf", 0, "")
	}
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", pinPath)
	}
	ta.log.Info(fmt.Sprintf("Detected mounted BPF filesystem at %v", pinPath))

	return nil
}

func isBPFMountFS(pinPath string) (bool, bool, error) {
	var st, pst unix.Stat_t

	err := unix.Lstat(pinPath, &st)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			// path doesn't exist
			return false, false, nil
		}
		return false, false, &os.PathError{Op: "lstat", Path: pinPath, Err: err}
	}

	parent := filepath.Dir(pinPath)
	err = unix.Lstat(parent, &pst)
	if err != nil {
		return false, false, &os.PathError{Op: "lstat", Path: parent, Err: err}
	}
	if st.Dev == pst.Dev {
		// parent has the same dev -- not a mount point
		return false, false, nil
	}

	fst := unix.Statfs_t{}
	err = unix.Statfs(pinPath, &fst)
	if err != nil {
		return true, false, &os.PathError{Op: "statfs", Path: pinPath, Err: err}
	}

	return true, int64(fst.Type) == unix.BPF_FS_MAGIC, nil
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
