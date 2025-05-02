package discover

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/generictracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/gotracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/gpuevent"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/httptracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tctracer"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tpinjector"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

type ProcessFinder struct {
	cfg         *beyla.Config
	ctxInfo     *global.ContextInfo
	tracesInput *msg.Queue[[]request.Span]
}

func NewProcessFinder(cfg *beyla.Config, ctxInfo *global.ContextInfo, tracesInput *msg.Queue[[]request.Span]) *ProcessFinder {
	return &ProcessFinder{cfg: cfg, ctxInfo: ctxInfo, tracesInput: tracesInput}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(ctx context.Context) (<-chan Event[*ebpf.Instrumentable], error) {

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))

	swi := swarm.Instancer{}
	processEvents := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(swarm.DirectInstance(ProcessWatcherFunc(pf.cfg, processEvents)))

	kubeEnrichedEvents := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, kubeEnrichedEvents))

	criteriaFilteredEvents := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(CriteriaMatcherProvider(pf.cfg, kubeEnrichedEvents, criteriaFilteredEvents))

	executableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, criteriaFilteredEvents, executableTypes))

	// we could subscribe ContainerDBUpdater directly to the executableTypes queue and not providing any output channel
	// but forcing the output by the executableTypesReplica channel only after the Container DB has been updated
	// prevents race conditions in later stages of the pipeline
	storedExecutableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(pf.cfg.ChannelBufferLen))
	swi.Add(ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, executableTypes, storedExecutableTypes))

	swi.Add(TraceAttacherProvider(&TraceAttacher{
		Cfg:                 pf.cfg,
		OutputTracerEvents:  tracerEvents,
		Metrics:             pf.ctxInfo.Metrics,
		SpanSignalsShortcut: pf.tracesInput,

		InputInstrumentables: storedExecutableTypes,
	}))

	pipeline, err := swi.Instance(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	tracerEventsCh := tracerEvents.Subscribe()
	pipeline.Start(ctx)
	return tracerEventsCh, nil
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

// the common tracer group should get loaded for any tracer group, only once
func newCommonTracersGroup(cfg *beyla.Config) []ebpf.Tracer {
	if cfg.EBPF.UseTCForL7CP {
		return []ebpf.Tracer{httptracer.New(cfg)}
	}

	tracers := []ebpf.Tracer{}

	switch cfg.EBPF.ContextPropagation {
	case config.ContextPropagationAll:
		if tctracer.CanRun() {
			tracers = append(tracers, tctracer.New(cfg))
		} else {
			slog.Warn("L4 trace context propagation cannot be enabled, missing host PID or host network access")
		}
		tracers = append(tracers, tpinjector.New(cfg))
	case config.ContextPropagationHeadersOnly:
		tracers = append(tracers, tpinjector.New(cfg))
	case config.ContextPropagationIPOptionsOnly:
		if tctracer.CanRun() {
			tracers = append(tracers, tctracer.New(cfg))
		} else {
			slog.Warn("L4 trace context propagation cannot be enabled, missing host PID or host network access")
		}
	}

	return tracers
}

func newGoTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{gotracer.New(cfg, metrics)}
}

func newGenericTracersGroup(cfg *beyla.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	if cfg.EBPF.InstrumentGPU {
		return []ebpf.Tracer{generictracer.New(cfg, metrics), gpuevent.New(cfg, metrics)}
	}
	return []ebpf.Tracer{generictracer.New(cfg, metrics)}
}
