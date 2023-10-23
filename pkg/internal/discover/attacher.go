package discover

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/cilium/ebpf/link"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// TraceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type TraceAttacher struct {
	Cfg               *pipe.Config
	Ctx               context.Context
	DiscoveredTracers chan *ebpf.ProcessTracer
	Metrics           imetrics.Reporter

	log *slog.Logger
}

func TraceAttacherProvider(ta TraceAttacher) (node.TerminalFunc[[]Event[Instrumentable]], error) {
	ta.log = slog.With("component", "discover.TraceAttacher")
	return func(in <-chan []Event[Instrumentable]) {
	mainLoop:
		for instrumentables := range in {
			for _, instr := range instrumentables {
				if pt, ok := ta.getTracer(instr.Obj); ok {
					// we can create multiple tracers for the same executable (ran from different processes)
					// even if we just need to instrument the executable once. TODO: deduplicate
					ta.DiscoveredTracers <- pt
					if ta.Cfg.Discovery.SystemWide {
						ta.log.Info("system wide instrumentation. Creating a single instrumenter")
						break mainLoop
					}
				}
			}
		}
		// waiting until context is done, in the case of SystemWide instrumentation
		<-ta.Ctx.Done()
	}, nil
}

func (ta *TraceAttacher) getTracer(ie Instrumentable) (*ebpf.ProcessTracer, bool) {
	// gets the
	var programs []ebpf.Tracer
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		programs = filterNotFoundPrograms(newGoTracersGroup(ta.Cfg, ta.Metrics), ie.Offsets)
	case svc.InstrumentableJava, svc.InstrumentableNodejs, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust:
		// We are not instrumenting a Go application, we override the programs
		// list with the generic kernel/socket space filters
		programs = newNonGoTracersGroup(ta.Cfg, ta.Metrics)
	default:
		ta.log.Warn("unexpected instrumentable type. This is basically a bug", "type", ie.Type)
	}
	if len(programs) == 0 {
		ta.log.Warn("no instrumentable functions found. Ignoring", "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		return nil, false
	}

	ie.FileInfo.Service = svc.ID{Name: ie.FileInfo.Service.Name, Namespace: ie.FileInfo.Service.Namespace, SDKLanguage: ie.Type}

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(ie.FileInfo.ProExeLinkPath)
	if err != nil {
		ta.log.Warn("can't open executable. Ignoring",
			"error", err, "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		return nil, false
	}

	return &ebpf.ProcessTracer{
		Programs:   programs,
		ELFInfo:    ie.FileInfo,
		Goffsets:   ie.Offsets,
		Exe:        exe,
		PinPath:    path.Join(ta.Cfg.EBPF.BpfBaseDir, fmt.Sprintf("%d-%d", os.Getpid(), ie.FileInfo.Pid)),
		SystemWide: ta.Cfg.Discovery.SystemWide,
	}, true
}

// filterNotFoundPrograms will filter these programs whose required functions (as
// returned in the Offsets method) haven't been found in the offsets
func filterNotFoundPrograms(programs []ebpf.Tracer, offsets *goexec.Offsets) []ebpf.Tracer {
	var filtered []ebpf.Tracer
	funcs := offsets.Funcs
programs:
	for _, p := range programs {
		for fn, fp := range p.GoProbes() {
			if !fp.Required {
				continue
			}
			if _, ok := funcs[fn]; !ok {
				continue programs
			}
		}
		filtered = append(filtered, p)
	}
	return filtered
}
