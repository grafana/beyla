package discover

import (
	"context"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/otelsdk"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
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
	beylaPID          int

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[uint64]

	// keeps a copy of all the tracers for a given executable path
	existingTracers     map[uint64]*ebpf.ProcessTracer
	sdkInjector         *otelsdk.SDKInjector
	reusableTracer      *ebpf.ProcessTracer
	reusableGoTracer    *ebpf.ProcessTracer
	commonTracersLoaded bool

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
	ta.sdkInjector = otelsdk.NewSDKInjector(ta.Cfg)
	ta.processInstances = maps.MultiCounter[uint64]{}
	ta.beylaPID = os.Getpid()

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	return func(in <-chan []Event[ebpf.Instrumentable]) {
	mainLoop:
		for instrumentables := range in {
			for _, instr := range instrumentables {
				ta.log.Debug("Instrumentable", "created", instr.Type, "type", instr.Obj.Type,
					"exec", instr.Obj.FileInfo.CmdExePath, "pid", instr.Obj.FileInfo.Pid)
				switch instr.Type {
				case EventCreated:
					sdkInstrumented := false
					if ta.sdkInjectionPossible(&instr.Obj) {
						if err := ta.sdkInjector.NewExecutable(&instr.Obj); err == nil {
							sdkInstrumented = true
						}
					}

					if !sdkInstrumented {
						ta.processInstances.Inc(instr.Obj.FileInfo.Ino)
						if ok := ta.getTracer(&instr.Obj); ok {
							ta.DiscoveredTracers <- &instr.Obj
							if ta.Cfg.Discovery.SystemWide {
								ta.log.Info("system wide instrumentation. Creating a single instrumenter")
								break mainLoop
							}
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

//nolint:cyclop
func (ta *TraceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Debug("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"child", ie.ChildPids,
			"exec", ie.FileInfo.CmdExePath)
		ie.FileInfo.Service.SDKLanguage = ie.Type
		// allowing the tracer to forward traces from the new PID and its children processes
		ta.monitorPIDs(tracer, ie)
		ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
		if tracer.Type == ebpf.Generic {
			// We need to do this because generic tracers have shared libraries. For example,
			// a python executable can run an SSL and non-SSL application, so it's not enough
			// to look at the executable, we must ensure this process doesn't have different
			// libraries attached
			ok = ta.updateTracerProbes(tracer, ie)
		} else {
			ta.monitorPIDs(ta.reusableGoTracer, ie)
		}
		ta.log.Debug(".done", "success", ok)
		return ok
	}

	ta.log.Info("instrumenting process",
		"cmd", ie.FileInfo.CmdExePath, "pid", ie.FileInfo.Pid, "ino", ie.FileInfo.Ino, "type", ie.Type)
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())

	// builds a tracer for that executable
	var programs []ebpf.Tracer
	tracerType := ebpf.Generic
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		if ta.Cfg.Discovery.SkipGoSpecificTracers || ta.Cfg.Discovery.SystemWide || ie.InstrumentationError != nil || ie.Offsets == nil {
			if ie.InstrumentationError != nil {
				ta.log.Warn("Unsupported Go program detected, using generic instrumentation", "error", ie.InstrumentationError)
			} else if ie.Offsets == nil {
				ta.log.Warn("Go program with null offsets detected, using generic instrumentation")
			}
			if ta.reusableTracer != nil {
				// We need to do more than monitor PIDs. It's possible that this new
				// instance of the executable has different DLLs loaded, e.g. libssl.so.
				return ta.reuseTracer(ta.reusableTracer, ie)
			} else {
				programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.Cfg, ta.Metrics))
			}
		} else {
			if ta.reusableGoTracer != nil {
				return ta.reuseTracer(ta.reusableGoTracer, ie)
			}
			tracerType = ebpf.Go
			programs = ta.withCommonTracersGroup(newGoTracersGroup(ta.Cfg, ta.Metrics))
		}
	case svc.InstrumentableNodejs, svc.InstrumentableJava, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP:
		if ta.reusableTracer != nil {
			return ta.reuseTracer(ta.reusableTracer, ie)
		}
		programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.Cfg, ta.Metrics))
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
		"exec", ie.FileInfo.CmdExePath,
		"type", ie.Type)
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

func (ta *TraceAttacher) withCommonTracersGroup(tracers []ebpf.Tracer) []ebpf.Tracer {
	if ta.commonTracersLoaded {
		return tracers
	}

	ta.commonTracersLoaded = true
	tracers = append(tracers, newCommonTracersGroup(ta.Cfg)...)

	return tracers
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

func (ta *TraceAttacher) reuseTracer(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	exe, ok := ta.loadExecutable(ie)
	if !ok {
		return false
	}

	if err := tracer.NewExecutable(exe, ie); err != nil {
		ta.log.Debug("Failed to attach uprobes for new executable", "pid", ie.FileInfo.Pid, "error", err)
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"exec", ie.FileInfo.CmdExePath,
		"language", ie.Type)

	ta.monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.Ino] = tracer

	return true
}

func (ta *TraceAttacher) updateTracerProbes(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	if err := tracer.NewExecutableInstance(ie); err != nil {
		ta.log.Debug("Failed to attach uprobes", "pid", ie.FileInfo.Pid, "error", err)
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"exec", ie.FileInfo.CmdExePath,
		"language", ie.Type)

	ta.monitorPIDs(tracer, ie)

	return true
}

func (ta *TraceAttacher) monitorPIDs(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) {
	// If the user does not override the service name via configuration
	// the service name is the name of the found executable
	// Unless the case of system-wide tracing, where the name of the
	// executable will be dynamically set for each traced http request call.
	if ie.FileInfo.Service.UID.Name == "" {
		ie.FileInfo.Service.UID.Name = ie.FileInfo.ExecutableName()
		// we mark the service ID as automatically named in case we want to look,
		// in later stages of the pipeline, for better automatic service name
		ie.FileInfo.Service.SetAutoName()
	}

	ie.FileInfo.Service.SDKLanguage = ie.Type

	// allowing the tracer to forward traces from the discovered PID and its children processes
	tracer.AllowPID(uint32(ie.FileInfo.Pid), ie.FileInfo.Ns, &ie.FileInfo.Service)
	for _, pid := range ie.ChildPids {
		tracer.AllowPID(pid, ie.FileInfo.Ns, &ie.FileInfo.Service)
	}
	if ta.SpanSignalsShortcut != nil {
		spans := make([]request.Span, 0, len(ie.ChildPids)+1)
		// the forwarded signal must include
		// - Service, which includes several metadata about the process
		// - PID namespace, to allow further kubernetes decoration
		spans = append(spans, request.Span{
			Type:    request.EventTypeProcessAlive,
			Service: ie.FileInfo.Service,
			Pid:     request.PidInfo{Namespace: ie.FileInfo.Ns},
		})
		for _, pid := range ie.ChildPids {
			service := ie.FileInfo.Service
			service.ProcPID = int32(pid)
			spans = append(spans, request.Span{
				Type:    request.EventTypeProcessAlive,
				Service: service,
				Pid:     request.PidInfo{Namespace: ie.FileInfo.Ns},
			})
		}
		ta.SpanSignalsShortcut <- spans
	}
}

func (ta *TraceAttacher) notifyProcessDeletion(ie *ebpf.Instrumentable) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Debug("process ended for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"exec", ie.FileInfo.CmdExePath)
		// notifying the tracer to block any trace from that PID
		// to avoid that a new process reusing this PID could send traces
		// unless explicitly allowed
		ta.Metrics.UninstrumentProcess(ie.FileInfo.ExecutableName())
		tracer.BlockPID(uint32(ie.FileInfo.Pid), ie.FileInfo.Ns)

		// if there are no more trace instances for a program, we need to notify that
		// the tracer needs to be stopped and deleted.
		// We don't remove kernel-based traces as there is only one tracer per host
		if ta.processInstances.Dec(ie.FileInfo.Ino) == 0 {
			delete(ta.existingTracers, ie.FileInfo.Ino)
			ie.Tracer = tracer
			ta.DeleteTracers <- ie
		}
	}
}

func (ta *TraceAttacher) sdkInjectionPossible(ie *ebpf.Instrumentable) bool {
	return ta.sdkInjector.Enabled() && ie.Type == svc.InstrumentableJava
}
