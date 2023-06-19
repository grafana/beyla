package ebpf

import (
	"fmt"
	"io"

	"github.com/cilium/ebpf/link"
	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/exec"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
	"golang.org/x/exp/slog"
)

type instrumenter struct {
	offsets   *goexec.Offsets
	exe       *link.Executable
	closables []io.Closer
}

func (i *instrumenter) goprobes(p Tracer) error {
	// TODO: not running program if it does not find the required probes
	for funcName, funcPrograms := range p.GoProbes() {
		offs, ok := i.offsets.Funcs[funcName]
		if !ok {
			// the program function is not in the detected offsets. Ignoring
			continue
		}
		slog.Debug("going to instrument function", "function", funcName, "offsets", offs, "programs", funcPrograms)
		if err := i.goprobe(ebpfcommon.Probe{
			Offsets:  offs,
			Programs: funcPrograms,
		}); err != nil {
			return fmt.Errorf("instrumenting function %q: %w", funcName, err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) goprobe(probe ebpfcommon.Probe) error {
	// Attach BPF programs as start and return probes
	if probe.Programs.Start != nil {
		up, err := i.exe.Uprobe("", probe.Programs.Start, &link.UprobeOptions{
			Address: probe.Offsets.Start,
		})
		if err != nil {
			return fmt.Errorf("setting uprobe: %w", err)
		}
		i.closables = append(i.closables, up)
	}

	if probe.Programs.End != nil {
		// Go won't work with Uretprobes because of the way Go manages the stack. We need to set uprobes just before the return
		// values: https://github.com/iovisor/bcc/issues/1320
		for _, ret := range probe.Offsets.Returns {
			urp, err := i.exe.Uprobe("", probe.Programs.End, &link.UprobeOptions{
				Address: ret,
			})
			if err != nil {
				return fmt.Errorf("setting uretprobe: %w", err)
			}
			i.closables = append(i.closables, urp)
		}
	}

	return nil
}

func (i *instrumenter) kprobes(p Tracer) error {
	for kfunc, kprobes := range p.KProbes() {
		slog.Debug("going to add kprobe to function", "function", kfunc, "probes", kprobes)

		if err := i.kprobe(kfunc, kprobes); err != nil {
			return fmt.Errorf("instrumenting function %q: %w", kfunc, err)
		}
		p.AddCloser(i.closables...)
	}

	return nil
}

func (i *instrumenter) kprobe(funcName string, programs ebpfcommon.FunctionPrograms) error {
	if programs.Start != nil {
		kp, err := link.Kprobe(funcName, programs.Start, nil)
		if err != nil {
			return fmt.Errorf("setting kprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	if programs.End != nil {
		kp, err := link.Kretprobe(funcName, programs.End, nil)
		if err != nil {
			return fmt.Errorf("setting kretprobe: %w", err)
		}
		i.closables = append(i.closables, kp)
	}

	return nil
}

func (i *instrumenter) uprobes(pid int32, p Tracer) error {
	maps, err := processMaps(pid)
	if err != nil {
		return err
	}

	if len(maps) == 0 {
		logger().Info("didn't find any process maps, not instrumenting shared libraries", "pid", pid)
		return nil
	}

	for lib, pMap := range p.UProbes() {
		logger().Info("finding library", "lib", lib)
		libMap := exec.LibPath(lib, maps)

		if libMap == nil {
			continue
		}

		logger().Info("instrumenting library", "lib", lib, "path", libMap.Pathname)

		// we do this to make sure instrumenting something like libssl.so works with Docker
		libExe, err := link.OpenExecutable(fmt.Sprintf("/proc/%d/map_files/%x-%x", pid, libMap.StartAddr, libMap.EndAddr))

		if err != nil {
			return err
		}

		for funcName, funcPrograms := range pMap {
			slog.Debug("going to instrument function", "function", funcName, "programs", funcPrograms)
			if err := i.uprobe(funcName, libExe, funcPrograms); err != nil {
				if funcPrograms.Required {
					return fmt.Errorf("instrumenting function %q: %w", funcName, err)
				}

				slog.Info("error instrumenting uprobe", "function", funcName, "error", err)
			}
			p.AddCloser(i.closables...)
		}
	}

	return nil
}

func (i *instrumenter) uprobe(funcName string, exe *link.Executable, probe ebpfcommon.FunctionPrograms) error {
	if probe.Start != nil {
		up, err := exe.Uprobe(funcName, probe.Start, nil)
		if err != nil {
			return fmt.Errorf("setting uprobe: %w", err)
		}
		i.closables = append(i.closables, up)
	}

	if probe.End != nil {
		up, err := exe.Uretprobe(funcName, probe.End, nil)
		if err != nil {
			return fmt.Errorf("setting uretprobe: %w", err)
		}
		i.closables = append(i.closables, up)
	}

	return nil
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
