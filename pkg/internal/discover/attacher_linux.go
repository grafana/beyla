package discover

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/internal/helpers"
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

func UnmountBPFFS(pinPath string, log *slog.Logger) {
	if err := unix.Unmount(pinPath, unix.MNT_FORCE|unix.MNT_DETACH); err != nil {
		log.Debug("can't unmount pinned root. Try unmounting and removing it manually", "error", err)
	}
	log.Debug("unmounted bpf file system")
	if err := os.RemoveAll(pinPath); err != nil {
		log.Warn("can't remove pinned root. Try removing it manually", "error", err)
	} else {
		log.Debug("removed pin path")
	}
}

func (ta *TraceAttacher) unmountBpfPinPath() {
	UnmountBPFFS(ta.pinPath, ta.log)
}

func (ta *TraceAttacher) bpfMount(pinPath string) error {
	mounted, bpffsInstance, err := IsMountFS(FilesystemTypeBPFFS, pinPath)
	if err != nil {
		return err
	}
	if !mounted {
		caps, err := helpers.GetCurrentProcCapabilities()

		if err == nil && !caps.Has(unix.CAP_SYS_ADMIN) {
			return fmt.Errorf("beyla requires CAP_SYS_ADMIN in order to mount %s", pinPath)
		}

		return unix.Mount(pinPath, pinPath, "bpf", 0, "")
	}
	if !bpffsInstance {
		return fmt.Errorf("mount in the custom directory %s has a different filesystem than BPFFS", pinPath)
	}
	ta.log.Info(fmt.Sprintf("Detected mounted BPF filesystem at %v", pinPath))

	return nil
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
