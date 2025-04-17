//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"

	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
)

func ilog() *slog.Logger {
	return slog.With("component", "ebpf.Instrumenter")
}

func closeAll(closers []io.Closer) {
	for i := range closers {
		closers[i].Close()
	}
}

func (i *instrumenter) instrumentProbes(exe *link.Executable, probes map[string][]*ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	log := ilog().With("probes", "instrumentProbes")

	var closers []io.Closer

	for symbolName, probeArray := range probes {
		for _, probe := range probeArray {
			log.Debug("going to instrument function", "function", symbolName, "programs", probe)

			cls, err := uprobe(exe, probe)

			if err != nil {
				closeAll(cls)

				if probe.Required {
					closeAll(closers)

					return nil, fmt.Errorf("instrumenting function %q: %w", symbolName, err)
				}

				// error will be common here since this could be no openssl loaded
				log.Debug("error instrumenting uprobe", "function", symbolName, "error", err)
			} else {
				closers = append(closers, cls...)
			}
		}
	}

	return closers, nil
}

func (i *instrumenter) kprobes(p KprobesTracer) error {
	log := ilog().With("probes", "kprobes")
	for kfunc, kprobes := range p.KProbes() {
		log.Debug("going to add kprobe to function", "function", kfunc, "probes", kprobes)

		if err := i.kprobe(kfunc, kprobes); err != nil {
			if kprobes.Required {
				return fmt.Errorf("instrumenting function %q: %w", kfunc, err)
			}

			log.Debug("error instrumenting kprobe", "function", kfunc, "error", err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) kprobe(funcName string, programs ebpfcommon.ProbeDesc) error {
	if programs.Start != nil {
		kp, err := link.Kprobe(funcName, programs.Start, nil)
		if err != nil {
			return fmt.Errorf("setting kprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	if programs.End != nil {
		// The commented code doesn't work on certain kernels. We need to invesigate more to see if it's possible
		// to productize it. Failure says: "neither debugfs nor tracefs are mounted".
		kp, err := link.Kretprobe(funcName, programs.End, nil /*&link.KprobeOptions{RetprobeMaxActive: 1024}*/)
		if err != nil {
			return fmt.Errorf("setting kretprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

func uprobe(exe *link.Executable, probe *ebpfcommon.ProbeDesc) ([]io.Closer, error) {
	var closers []io.Closer

	if probe.Start != nil {
		up, err := exe.Uprobe("", probe.Start, &link.UprobeOptions{
			Address: probe.StartOffset,
		})

		if err != nil {
			return closers, fmt.Errorf("setting uprobe (offset): %w", err)
		}

		closers = append(closers, up)
	}

	if probe.End != nil {
		if len(probe.ReturnOffsets) == 0 {
			return closers, fmt.Errorf("setting uretprobe (attaching to offset): missing return offsets")
		}

		for _, offset := range probe.ReturnOffsets {
			up, err := exe.Uprobe("", probe.End, &link.UprobeOptions{
				Address: offset,
			})

			if err != nil {
				return closers, fmt.Errorf("setting uretprobe (attaching to offset): %w", err)
			}

			closers = append(closers, up)
		}
	}

	return closers, nil
}

func (i *instrumenter) sockfilters(p Tracer) error {
	for _, filter := range p.SocketFilters() {
		fd, err := attachSocketFilter(filter)
		if err != nil {
			return fmt.Errorf("attaching socket filter: %w", err)
		}

		p.AddCloser(&ebpfcommon.Filter{Fd: fd})
	}

	return nil
}

func attachSocketFilter(filter *ebpf.Program) (int, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err == nil {
		ssoErr := syscall.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, filter.FD())
		if ssoErr != nil {
			return -1, ssoErr
		}
		return fd, nil
	}

	return -1, err
}

func (i *instrumenter) sockmsgs(p Tracer) error {
	for _, sockmsg := range p.SockMsgs() {
		slog.Info("Attaching sock msgs")
		err := link.RawAttachProgram(link.RawAttachProgramOptions{
			Target:  sockmsg.MapFD,
			Program: sockmsg.Program,
			Attach:  sockmsg.AttachAs,
		})

		if err != nil {
			return fmt.Errorf("attaching sock_msg program: %w", err)
		}

		p.AddCloser(&sockmsg)
	}

	return nil
}

func (i *instrumenter) sockops(p Tracer) error {
	for _, sockops := range p.SockOps() {
		cgroupPath, err := getCgroupPath()

		if err != nil {
			return fmt.Errorf("error getting cgroup path for sockops: %w", err)
		}

		slog.Info("Attaching sock ops", "path", cgroupPath)

		sockops.SockopsCgroup, err = link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  sockops.AttachAs,
			Program: sockops.Program,
		})

		if err != nil {
			return fmt.Errorf("attaching sockops program: %w", err)
		}

		p.AddCloser(&sockops)
	}

	return nil
}

func (i *instrumenter) tracepoints(p KprobesTracer) error {
	for sfunc, sprobes := range p.Tracepoints() {
		slog.Debug("going to add syscall", "function", sfunc, "probes", sprobes)

		if err := i.tracepoint(sfunc, sprobes); err != nil {
			return fmt.Errorf("instrumenting function %q: %w", sfunc, err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) tracepoint(funcName string, programs ebpfcommon.ProbeDesc) error {
	if programs.Start != nil {
		if !strings.Contains(funcName, "/") {
			return fmt.Errorf("invalid tracepoint type, must contain / in the name to separate the type and function name")
		}
		parts := strings.Split(funcName, "/")
		kp, err := link.Tracepoint(parts[0], parts[1], programs.Start, nil)
		if err != nil {
			return fmt.Errorf("setting syscall: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

func (i *instrumenter) addModule(ino uint64) {
	slog.Debug("remembering module for", "instrumenter", i, "ino", ino)
	i.modules[ino] = struct{}{}
}

func isLittleEndian() bool {
	var a uint16 = 1

	return *(*byte)(unsafe.Pointer(&a)) == 1
}

func htons(a uint16) uint16 {
	if isLittleEndian() {
		var arr [2]byte
		binary.LittleEndian.PutUint16(arr[:], a)
		return binary.BigEndian.Uint16(arr[:])
	}
	return a
}

func getCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := v2.Enabled()
	if !enabled {
		if _, pathErr := os.Stat(filepath.Join(cgroupPath, "unified")); pathErr == nil {
			slog.Debug("discovered hybrid cgroup hierarchy, will attempt to attach sockops")
			return filepath.Join(cgroupPath, "unified"), nil
		}
		return "", errors.New("failed to find unified cgroup hierarchy: sockops cannot be used with cgroups v1")
	}
	return cgroupPath, err
}
