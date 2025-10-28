// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/otelsdk"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// traceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type traceAttacher struct {
	log     *slog.Logger
	Cfg     *obi.Config
	Metrics imetrics.Reporter
	obiPID  int

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[uint64]

	// keeps a copy of all the tracers for a given executable path
	existingTracers     map[uint64]*ebpf.ProcessTracer
	sdkInjector         *otelsdk.SDKInjector
	nodeInjector        *nodejs.NodeInjector
	reusableTracer      *ebpf.ProcessTracer
	reusableGoTracer    *ebpf.ProcessTracer
	commonTracersLoaded bool

	// Usually, only ebpf.Tracer implementations will send spans data to the read decorator.
	// But on each new process, we will send a "process alive" span type to the read decorator, whose
	// unique purpose is to notify other parts of the system that this process is active, even
	// if no spans are detected. This would allow, for example, to start instrumenting this process
	// from the Process metrics pipeline even before it starts to do/receive requests.
	SpanSignalsShortcut *msg.Queue[[]request.Span]

	// InputInstrumentables is the input channel for the traceAttacher, where it receives information
	// about the instrumentables that traversed the whole process discovery pipeline, so they need to
	// be instrumented.
	InputInstrumentables *msg.Queue[[]Event[ebpf.Instrumentable]]

	// OutputTracerEvents communicates the process discovery pipeline with the instrumentation pipeline.
	// This queue will forward any newly discovered process to the instrumentation pipeline.
	OutputTracerEvents *msg.Queue[Event[*ebpf.Instrumentable]]

	// EbpfEventContext allows to set the common PID filter that's used to filter out events we don't need
	EbpfEventContext *ebpfcommon.EBPFEventContext

	// Extracts HTTP routes from executables
	routeHarvester *harvest.RouteHarvester
}

func traceAttacherProvider(ta *traceAttacher) swarm.InstanceFunc {
	return ta.attacherLoop
}

func (ta *traceAttacher) attacherLoop(_ context.Context) (swarm.RunFunc, error) {
	ta.log = slog.With("component", "discover.traceAttacher")
	ta.existingTracers = map[uint64]*ebpf.ProcessTracer{}
	ta.sdkInjector = otelsdk.NewSDKInjector(ta.Cfg)
	ta.nodeInjector = nodejs.NewNodeInjector(ta.Cfg)
	ta.processInstances = maps.MultiCounter[uint64]{}
	ta.obiPID = os.Getpid()
	ta.EbpfEventContext.CommonPIDsFilter = ebpfcommon.CommonPIDsFilter(&ta.Cfg.Discovery, ta.Metrics)
	ta.routeHarvester = harvest.NewRouteHarvester(ta.Cfg.Discovery.DisabledRouteHarvesters, ta.Cfg.Discovery.RouteHarvesterTimeout)

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	in := ta.InputInstrumentables.Subscribe(msg.SubscriberName("traceAttacher"))
	return func(ctx context.Context) {
		defer ta.OutputTracerEvents.Close()
		swarms.ForEachInput(ctx, in, ta.log.Debug, func(instrumentables []Event[ebpf.Instrumentable]) {
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
						ta.nodeInjector.NewExecutable(&instr.Obj)

						ta.processInstances.Inc(instr.Obj.FileInfo.Ino)
						if ok := ta.getTracer(&instr.Obj); ok {
							ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventCreated, Obj: &instr.Obj})
						}

						if instr.Obj.FileInfo.ELF != nil {
							_ = instr.Obj.FileInfo.ELF.Close()
						}
					}
				case EventDeleted:
					ta.notifyProcessDeletion(&instr.Obj)
				}
			}
		})
	}, nil
}

//nolint:cyclop
func (ta *traceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Debug("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid,
			"child", ie.ChildPids,
			"cmd", ie.FileInfo.CmdExePath)
		ie.FileInfo.Service.SDKLanguage = ie.Type
		// Must be called after we've set the SDKLanguage
		ta.harvestRoutes(ie, false)

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
		"cmd", ie.FileInfo.CmdExePath,
		"pid", ie.FileInfo.Pid,
		"ino", ie.FileInfo.Ino,
		"type", ie.Type,
		"service", ie.FileInfo.Service.UID.Name,
	)

	// builds a tracer for that executable
	var programs []ebpf.Tracer
	tracerType := ebpf.Generic
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		if ta.Cfg.Discovery.SkipGoSpecificTracers || ie.InstrumentationError != nil || ie.Offsets == nil {
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
				programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
			}
		} else {
			if ta.reusableGoTracer != nil {
				return ta.reuseTracer(ta.reusableGoTracer, ie)
			}
			tracerType = ebpf.Go
			programs = ta.withCommonTracersGroup(newGoTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
		}
	case svc.InstrumentableNodejs, svc.InstrumentableJava, svc.InstrumentableJavaNative, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP:
		if ta.reusableTracer != nil {
			return ta.reuseTracer(ta.reusableTracer, ie)
		}
		programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
	default:
		ta.log.Warn("unexpected instrumentable type. This is basically a bug", "type", ie.Type)
	}
	if len(programs) == 0 {
		ta.log.Warn("no instrumentable functions found. Ignoring", "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorNoInstrumentableFunctionsFound)
		return false
	}

	ie.FileInfo.Service.SDKLanguage = ie.Type
	// Must be called after we've set the SDKLanguage
	ta.harvestRoutes(ie, false)

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, ok := ta.loadExecutable(ie)
	if !ok {
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}

	tracer := ebpf.NewProcessTracer(tracerType, programs, ta.Cfg.ShutdownTimeout, ta.Metrics)

	if err := tracer.Init(ta.EbpfEventContext); err != nil {
		ta.log.Error("couldn't trace process. Stopping process tracer", "error", err)
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}

	ie.Tracer = tracer

	if err := tracer.NewExecutable(exe, ie); err != nil {
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorAttachingUprobe)
		return false
	}

	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath,
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
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
	ta.log.Debug(".done")
	return true
}

func (ta *traceAttacher) withCommonTracersGroup(tracers []ebpf.Tracer) []ebpf.Tracer {
	if ta.commonTracersLoaded {
		return tracers
	}

	ta.commonTracersLoaded = true
	tracers = append(tracers, newCommonTracersGroup(ta.Cfg)...)

	return tracers
}

func (ta *traceAttacher) harvestRoutes(ie *ebpf.Instrumentable, reused bool) {
	routes, err := ta.routeHarvester.HarvestRoutes(ie.FileInfo)
	if err != nil {
		ta.log.Info("encountered error harvesting routes", "error", err, "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
	} else if routes != nil && len(routes.Routes) > 0 {
		ta.log.Debug("found routes in executable", "pid", ie.FileInfo.Pid, "routes", routes, "reused", reused)
		m := harvest.RouteMatcherFromResult(*routes)
		ie.FileInfo.Service.SetHarvestedRoutes(m)
	}
}

func (ta *traceAttacher) loadExecutable(ie *ebpf.Instrumentable) (*link.Executable, bool) {
	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(ie.FileInfo.ProExeLinkPath)
	if err != nil {
		ta.log.Debug("can't open executable. Ignoring",
			"error", err, "pid", ie.FileInfo.Pid, "cmd", ie.FileInfo.CmdExePath)
		return nil, false
	}

	return exe, true
}

func (ta *traceAttacher) reuseTracer(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
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
		"cmd", ie.FileInfo.CmdExePath,
		"language", ie.Type)

	ta.monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.Ino] = tracer
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())

	return true
}

func (ta *traceAttacher) updateTracerProbes(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	if err := tracer.NewExecutableInstance(ie); err != nil {
		ta.log.Debug("Failed to attach uprobes", "pid", ie.FileInfo.Pid, "error", err)
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid,
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath,
		"language", ie.Type)

	ta.monitorPIDs(tracer, ie)

	return true
}

func (ta *traceAttacher) monitorPIDs(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) {
	ie.CopyToServiceAttributes()

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
		ta.SpanSignalsShortcut.Send(spans)
	}
}

func (ta *traceAttacher) notifyProcessDeletion(ie *ebpf.Instrumentable) {
	if tracer, ok := ta.existingTracers[ie.FileInfo.Ino]; ok {
		ta.log.Info("process ended for already instrumented executable",
			"cmd", ie.FileInfo.CmdExePath,
			"pid", ie.FileInfo.Pid,
			"ino", ie.FileInfo.Ino,
			"type", ie.Type,
			"service", ie.FileInfo.Service.UID.Name,
		)
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
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventDeleted, Obj: ie})
		} else {
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventInstanceDeleted, Obj: ie})
		}
	}
}

func (ta *traceAttacher) sdkInjectionPossible(ie *ebpf.Instrumentable) bool {
	return ta.sdkInjector.Enabled() && ie.Type == svc.InstrumentableJava
}

func (ta *traceAttacher) init() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	return nil
}
