package discover

import (
	"context"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/ebpf"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// TraceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type TraceAttacher struct {
	log               *slog.Logger
	Cfg               *beyla.Config
	Ctx               context.Context
	DiscoveredTracers chan *ebpf.Instrumentable
	DeleteTracers     chan *ebpf.Instrumentable
	Metrics           imetrics.Reporter
	pinPath           string
	beylaPID          int

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[uint64]

	// keeps a copy of all the tracers for a given executable path
	existingTracers  map[uint64]*ebpf.ProcessTracer
	reusableTracer   *ebpf.ProcessTracer
	reusableGoTracer *ebpf.ProcessTracer

	// Usually, only ebpf.Tracer implementations will send spans data to the read decorator.
	// But on each new process, we will send a "process alive" span type to the read decorator, whose
	// unique purpose is to notify other parts of the system that this process is active, even
	// if no spans are detected. This would allow, for example, to start instrumenting this process
	// from the Process metrics pipeline even before it starts to do/receive requests.
	SpanSignalsShortcut chan<- []request.Span
}

func TraceAttacherProvider(ta *TraceAttacher) pipe.FinalProvider[[]Event[ebpf.Instrumentable]] {
	return ta.attacherLoop
}

func (ta *TraceAttacher) attacherLoop() (pipe.FinalFunc[[]Event[ebpf.Instrumentable]], error) {
	ta.log = slog.With("component", "discover.TraceAttacher")
	ta.existingTracers = map[uint64]*ebpf.ProcessTracer{}
	ta.processInstances = maps.MultiCounter[uint64]{}
	ta.beylaPID = os.Getpid()
	ta.pinPath = ebpf.BuildPinPath(ta.Cfg)

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	return func(in <-chan []Event[ebpf.Instrumentable]) {
	mainLoop:
		for instrumentables := range in {
			for _, instr := range instrumentables {
				ta.log.Debug("Instrumentable", "len", len(instrumentables), "inst", instr)
				switch instr.Type {
				case EventCreated:
					ta.processInstances.Inc(instr.Obj.FileInfo.Ino)
					if ok := ta.getTracer(&instr.Obj); ok {
						ta.DiscoveredTracers <- &instr.Obj
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
		ta.log.Debug("terminating process attacher")
		ta.close()
	}, nil
}

func (ta *TraceAttacher) skipSelfInstrumentation(ie *ebpf.Instrumentable) bool {
	return ie.FileInfo.Pid == int32(ta.beylaPID) && !ta.Cfg.Discovery.AllowSelfInstrumentation
}

//nolint:cyclop
func (ta *TraceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Info("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"child", ie.ChildPids,
			"exec", ie.FileInfo.CmdExePath)
		ie.FileInfo.Service.SDKLanguage = ie.Type
		// allowing the tracer to forward traces from the new PID and its children processes
		ta.monitorPIDs(tracer, ie)
		ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
		if tracer.Type == ebpf.Generic {
			ta.monitorPIDs(ta.reusableTracer, ie)
		} else {
			ta.monitorPIDs(ta.reusableGoTracer, ie)
		}
		ta.log.Debug(".done")
		return ok
	}

	if ta.skipSelfInstrumentation(ie) {
		ta.log.Info("skipping self-instrumentation of Beyla process", "cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid)
		return false
	}

	ta.log.Info("instrumenting process", "cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid, "ino", ie.FileInfo.Ino)
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
			if ta.reusableGoTracer != nil {
				exe, ok := ta.loadExecutable(ie)
				if !ok {
					return false
				}

				if err := ta.reusableGoTracer.NewExecutable(exe, ie); err != nil {
					return false
				}

				ta.log.Debug("reusing Go tracer for",
					"pid", ie.FileInfo.Pid,
					"child", ie.ChildPids,
					"exec", ie.FileInfo.CmdExePath)

				ta.monitorPIDs(ta.reusableGoTracer, ie)
				ta.existingTracers[ie.FileInfo.Ino] = ta.reusableGoTracer

				return true
			}
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
		return false
	}

	ie.FileInfo.Service.SDKLanguage = ie.Type

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, ok := ta.loadExecutable(ie)
	if !ok {
		return false
	}

	tracer := ebpf.NewProcessTracer(ta.Cfg, tracerType, programs)

	if err := tracer.Init(); err != nil {
		ta.log.Error("couldn't trace process. Stopping process tracer", "error", err)
		return false
	}

	ie.Tracer = tracer

	if err := tracer.NewExecutable(exe, ie); err != nil {
		return false
	}

	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"exec", ie.FileInfo.CmdExePath)
	// allowing the tracer to forward traces from the discovered PID and its children processes
	ta.monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.Ino] = tracer
	if tracer.Type == ebpf.Generic {
		if ta.reusableTracer != nil {
			ta.monitorPIDs(ta.reusableTracer, ie)
		} else {
			ta.reusableTracer = tracer
		}
	} else {
		ta.reusableGoTracer = tracer
	}
	ta.log.Debug(".done")
	return true
}

func (ta *TraceAttacher) loadExecutable(ie *ebpf.Instrumentable) (*link.Executable, bool) {
	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(ie.FileInfo.ProExeLinkPath)
	if err != nil {
		ta.log.Warn("can't open executable. Ignoring",
			"error", err, "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		return nil, false
	}

	return exe, true
}

func (ta *TraceAttacher) genericTracers() []ebpf.Tracer {
	if ta.reusableTracer != nil {
		return newNonGoTracersGroupUProbes(ta.Cfg, ta.Metrics)
	}

	return newNonGoTracersGroup(ta.Cfg, ta.Metrics)
}

func (ta *TraceAttacher) monitorPIDs(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) {
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
	if ta.SpanSignalsShortcut != nil {
		spans := make([]request.Span, 0, len(ie.ChildPids)+1)
		// the forwarded signal must include
		// - ServiceID, which includes several metadata about the process
		// - PID namespace, to allow further kubernetes decoration
		spans = append(spans, request.Span{
			Type:      request.EventTypeProcessAlive,
			ServiceID: ie.FileInfo.Service,
			Pid:       request.PidInfo{Namespace: ie.FileInfo.Ns},
		})
		for _, pid := range ie.ChildPids {
			service := ie.FileInfo.Service
			service.ProcPID = int32(pid)
			spans = append(spans, request.Span{
				Type:      request.EventTypeProcessAlive,
				ServiceID: service,
				Pid:       request.PidInfo{Namespace: ie.FileInfo.Ns},
			})
		}
		ta.SpanSignalsShortcut <- spans
	}
}

func (ta *TraceAttacher) notifyProcessDeletion(ie *ebpf.Instrumentable) {
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
			ie.Tracer = tracer
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
