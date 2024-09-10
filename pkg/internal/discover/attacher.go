package discover

import (
	"context"
	"log/slog"
	"os"
	"path"

	"github.com/cilium/ebpf/link"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// TraceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type TraceAttacher struct {
	log               *slog.Logger
	Cfg               *beyla.Config
	Ctx               context.Context
	DiscoveredTracers chan *ebpf.ProcessTracer
	DeleteTracers     chan *Instrumentable
	Metrics           imetrics.Reporter
	pinPath           string
	beylaPID          int

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[uint64]

	// keeps a copy of all the tracers for a given executable path
	existingTracers map[uint64]*ebpf.ProcessTracer
	reusableTracer  *ebpf.ProcessTracer
}

func TraceAttacherProvider(ta *TraceAttacher) pipe.FinalProvider[[]Event[Instrumentable]] {
	return ta.attacherLoop
}

func (ta *TraceAttacher) attacherLoop() (pipe.FinalFunc[[]Event[Instrumentable]], error) {
	ta.log = slog.With("component", "discover.TraceAttacher")
	ta.existingTracers = map[uint64]*ebpf.ProcessTracer{}
	ta.processInstances = maps.MultiCounter[uint64]{}
	ta.beylaPID = os.Getpid()
	ta.pinPath = BuildPinPath(ta.Cfg)

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	return func(in <-chan []Event[Instrumentable]) {
	mainLoop:
		for instrumentables := range in {
			for _, instr := range instrumentables {
				ta.log.Debug("Instrumentable", "len", len(instrumentables), "inst", instr)
				switch instr.Type {
				case EventCreated:
					ta.processInstances.Inc(instr.Obj.FileInfo.Ino)
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
		ta.close()
	}, nil
}

func (ta *TraceAttacher) skipSelfInstrumentation(ie *Instrumentable) bool {
	return ie.FileInfo.Pid == int32(ta.beylaPID) && !ta.Cfg.Discovery.AllowSelfInstrumentation
}

//nolint:cyclop
func (ta *TraceAttacher) getTracer(ie *Instrumentable) (*ebpf.ProcessTracer, bool) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Info("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"child", ie.ChildPids,
			"exec", ie.FileInfo.CmdExePath)
		ie.FileInfo.Service.SDKLanguage = ie.Type
		// allowing the tracer to forward traces from the new PID and its children processes
		monitorPIDs(tracer, ie)
		ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
		if tracer.Type == ebpf.Generic {
			monitorPIDs(ta.reusableTracer, ie)
		}
		ta.log.Debug(".done")
		return nil, false
	}

	if ta.skipSelfInstrumentation(ie) {
		ta.log.Info("skipping self-instrumentation of Beyla process", "cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)
		return nil, false
	}

	ta.log.Info("instrumenting process", "cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())

	// builds a tracer for that executable
	var programs []ebpf.Tracer
	tracerType := ebpf.Generic
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		if ta.Cfg.Discovery.SkipGoSpecificTracers || ie.InstrumentationError != nil {
			if ie.InstrumentationError != nil {
				ta.log.Warn("Unsupported Go program detected, using generic instrumentation", "error", ie.InstrumentationError)
			}
			if ta.reusableTracer != nil {
				programs = newNonGoTracersGroupUProbes(ta.Cfg, ta.Metrics)
			} else {
				programs = newNonGoTracersGroup(ta.Cfg, ta.Metrics)
			}
		} else {
			tracerType = ebpf.Go
			programs = filterNotFoundPrograms(newGoTracersGroup(ta.Cfg, ta.Metrics), ie.Offsets)
		}
	case svc.InstrumentableNodejs:
		programs = ta.genericTracers()
		programs = append(programs, newNodeJSTracersGroup(ta.Cfg, ta.Metrics)...)
	case svc.InstrumentableJava, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP:
		programs = ta.genericTracers()
	default:
		ta.log.Warn("unexpected instrumentable type. This is basically a bug", "type", ie.Type)
	}
	if len(programs) == 0 {
		ta.log.Warn("no instrumentable functions found. Ignoring", "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		return nil, false
	}

	ie.FileInfo.Service.SDKLanguage = ie.Type

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
		PinPath:    BuildPinPath(ta.Cfg),
		SystemWide: ta.Cfg.Discovery.SystemWide,
		Type:       tracerType,
	}
	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"exec", ie.FileInfo.CmdExePath)
	// allowing the tracer to forward traces from the discovered PID and its children processes
	monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.Ino] = tracer
	if tracer.Type == ebpf.Generic {
		if ta.reusableTracer != nil {
			monitorPIDs(ta.reusableTracer, ie)
		} else {
			ta.reusableTracer = tracer
		}
	}
	ta.log.Debug(".done")
	return tracer, true
}

func (ta *TraceAttacher) genericTracers() []ebpf.Tracer {
	if ta.reusableTracer != nil {
		return newNonGoTracersGroupUProbes(ta.Cfg, ta.Metrics)
	}

	return newNonGoTracersGroup(ta.Cfg, ta.Metrics)
}

func monitorPIDs(tracer *ebpf.ProcessTracer, ie *Instrumentable) {
	// If the user does not override the service name via configuration
	// the service name is the name of the found executable
	// Unless the case of system-wide tracing, where the name of the
	// executable will be dynamically set for each traced http request call.
	if ie.FileInfo.Service.Name == "" {
		ie.FileInfo.Service.Name = ie.FileInfo.ExecutableName()
		// we mark the service ID as automatically named in case we want to look,
		// in later stages of the pipeline, for better automatic service name
		ie.FileInfo.Service.SetAutoName()
	}

	// allowing the tracer to forward traces from the discovered PID and its children processes
	tracer.AllowPID(uint32(ie.FileInfo.Pid), ie.FileInfo.Ns, &ie.FileInfo.Service)
	for _, pid := range ie.ChildPids {
		tracer.AllowPID(pid, ie.FileInfo.Ns, &ie.FileInfo.Service)
	}
}

// BuildPinPath pinpath must be unique for a given executable group
// it will be:
//   - current beyla PID
func BuildPinPath(cfg *beyla.Config) string {
	return path.Join(cfg.EBPF.BpfBaseDir, cfg.EBPF.BpfPath)
}

func (ta *TraceAttacher) notifyProcessDeletion(ie *Instrumentable) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Info("process ended for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"exec", ie.FileInfo.CmdExePath)
		// notifying the tracer to block any trace from that PID
		// to avoid that a new process reusing this PID could send traces
		// unless explicitly allowed
		ta.Metrics.UninstrumentProcess(ie.FileInfo.ExecutableName())
		tracer.BlockPID(uint32(ie.FileInfo.Pid), ie.FileInfo.Ns)

		// if there are no more trace instances for a Go program, we need to notify that
		// the tracer needs to be stopped and deleted.
		// We don't remove kernel-based traces as there is only one tracer per host
		if tracer.Type != ebpf.Generic && ta.processInstances.Dec(ie.FileInfo.Ino) == 0 {
			delete(ta.existingTracers, ie.FileInfo.Ino)
			ta.DeleteTracers <- ie
		}
	}
}

// filterNotFoundPrograms will filter these programs whose required functions (as
// returned in the Offsets method) haven't been found in the offsets
func filterNotFoundPrograms(programs []ebpf.Tracer, offsets *goexec.Offsets) []ebpf.Tracer {
	if offsets == nil {
		return nil
	}
	var filtered []ebpf.Tracer
	funcs := offsets.Funcs
programs:
	for _, p := range programs {
		for funcName, funcPrograms := range p.GoProbes() {
			for _, fp := range funcPrograms {
				if !fp.Required {
					continue
				}
				if _, ok := funcs[funcName]; !ok {
					continue programs
				}
			}
		}
		filtered = append(filtered, p)
	}
	return filtered
}
