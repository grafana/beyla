package discover

import (
	"context"
	"fmt"
	"hash/fnv"
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
	log               *slog.Logger
	Cfg               *pipe.Config
	Ctx               context.Context
	DiscoveredTracers chan *ebpf.ProcessTracer
	Metrics           imetrics.Reporter

	// keeps a copy of all the tracers for a given executable path
	existingTracers map[string]*ebpf.ProcessTracer
}

func TraceAttacherProvider(ta TraceAttacher) (node.TerminalFunc[[]Event[Instrumentable]], error) {
	ta.log = slog.With("component", "discover.TraceAttacher")
	ta.existingTracers = map[string]*ebpf.ProcessTracer{}

	return func(in <-chan []Event[Instrumentable]) {
	mainLoop:
		for instrumentables := range in {
			for _, instr := range instrumentables {
				switch instr.Type {
				case EventCreated:
					if pt, ok := ta.getTracer(&instr.Obj); ok {
						ta.DiscoveredTracers <- pt
						if ta.Cfg.Discovery.SystemWide {
							ta.log.Info("system wide instrumentation. Creating a single instrumenter")
							break mainLoop
						}
					}
				case EventDeleted:
					ta.notifyProcessDeletion(&instr.Obj)
				}
			}
		}
		// waiting until context is done, in the case of SystemWide instrumentation
		<-ta.Ctx.Done()
	}, nil
}

func (ta *TraceAttacher) getTracer(ie *Instrumentable) (*ebpf.ProcessTracer, bool) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.CmdExePath]; ok {
		ta.log.Info("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"exec", ie.FileInfo.CmdExePath)
		// allowing the tracer to forward traces from the new PID
		tracer.AllowPID(uint32(ie.FileInfo.Pid))
		return nil, false
	}
	ta.log.Info("instrumenting process", "cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)

	// builds a tracer for that executable
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

	tracer := &ebpf.ProcessTracer{
		Programs:   programs,
		ELFInfo:    ie.FileInfo,
		Goffsets:   ie.Offsets,
		Exe:        exe,
		PinPath:    ta.buildPinPath(ie),
		SystemWide: ta.Cfg.Discovery.SystemWide,
	}
	// allowing the tracer to forward traces from the discovered PID
	tracer.AllowPID(uint32(ie.FileInfo.Pid))
	ta.existingTracers[ie.FileInfo.CmdExePath] = tracer
	return tracer, true
}

// pinpath must be unique for a given executable group
// it will be:
//   - current beyla PID
//   - PID of the first process that matched that executable
//     (don't mind if that process stops and other processes of the same executable keep using this pinPath)
//   - Hash of the executable path
//
// This way we prevent improbable (almost impossible) collisions of the exec hash
// or that the first process stopped and a different process with the same PID
// started, with a different executable
func (ta *TraceAttacher) buildPinPath(ie *Instrumentable) string {
	execHash := fnv.New32()
	_, _ = execHash.Write([]byte(ie.FileInfo.CmdExePath))
	return path.Join(ta.Cfg.EBPF.BpfBaseDir,
		fmt.Sprintf("%d-%d-%x", os.Getpid(), ie.FileInfo.Pid, execHash.Sum32()))
}

func (ta *TraceAttacher) notifyProcessDeletion(ie *Instrumentable) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.CmdExePath]; ok {
		ta.log.Info("process ended for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"exec", ie.FileInfo.CmdExePath)
		// notifying the tracer to block any trace from that PID
		// to avoid that a new process reusing this PID could send traces
		// unless explicitly allowed
		tracer.BlockPID(uint32(ie.FileInfo.Pid))
	}
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
