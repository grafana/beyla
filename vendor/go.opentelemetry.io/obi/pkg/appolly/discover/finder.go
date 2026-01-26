// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tctracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type ProcessFinder struct {
	cfg              *obi.Config
	ctxInfo          *global.ContextInfo
	tracesInput      *msg.Queue[[]request.Span]
	ebpfEventContext *ebpfcommon.EBPFEventContext
	doneChan         <-chan error
}

func NewProcessFinder(
	cfg *obi.Config,
	ctxInfo *global.ContextInfo,
	tracesInput *msg.Queue[[]request.Span],
	ebpfEventContext *ebpfcommon.EBPFEventContext,
) *ProcessFinder {
	return &ProcessFinder{cfg: cfg, ctxInfo: ctxInfo, tracesInput: tracesInput, ebpfEventContext: ebpfEventContext}
}

type processFinderStartConfig struct {
	enrichedProcessEvents *msg.Queue[[]Event[ProcessAttrs]]
}

// ProcessFinderStartOpt allows overriding some internal behavior of ProcessFinder.Start method.
// This is useful for vendoring OBI inside another collector
type ProcessFinderStartOpt func(*processFinderStartConfig)

// WithEnrichedProcessEvents allows overriding the enrichedProcessEvents internal communication queue.
// This is useful for components that vendor OBI and want to listen for process events that have been already
// enriched with extra metadata (e.g. Kubernetes)
func WithEnrichedProcessEvents(enrichedProcessEvents *msg.Queue[[]Event[ProcessAttrs]]) ProcessFinderStartOpt {
	return func(cfg *processFinderStartConfig) {
		cfg.enrichedProcessEvents = enrichedProcessEvents
	}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(ctx context.Context, opts ...ProcessFinderStartOpt) (<-chan Event[*ebpf.Instrumentable], error) {
	startConfig := processFinderStartConfig{}
	for _, opt := range opts {
		opt(&startConfig)
	}

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("tracerEvents"))

	swi := swarm.Instancer{}
	processEvents := msg.NewQueue[[]Event[ProcessAttrs]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("processEvents"))

	swi.Add(swarm.DirectInstance(ProcessWatcherFunc(pf.cfg, pf.ebpfEventContext, processEvents)),
		swarm.WithID("ProcessWatcher"))

	enrichedProcessEvents := startConfig.enrichedProcessEvents
	if enrichedProcessEvents == nil {
		enrichedProcessEvents = msg.NewQueue[[]Event[ProcessAttrs]](
			msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("enrichedProcessEvents"))
	}
	swi.Add(WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, enrichedProcessEvents),
		swarm.WithID("WatcherKubeEnricher"))

	criteriaFilteredEvents := msg.NewQueue[[]Event[ProcessMatch]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("criteriaFilteredEvents"))
	swi.Add(criteriaMatcherProvider(pf.cfg, enrichedProcessEvents, criteriaFilteredEvents),
		swarm.WithID("CriteriaMatcher"))

	executableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("executableTypes"))
	swi.Add(ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, criteriaFilteredEvents, executableTypes),
		swarm.WithID("ExecTyper"))

	// we could subscribe ContainerDBUpdater directly to the executableTypes queue and not providing any output channel
	// but forcing the output by the executableTypesReplica channel only after the Container DB has been updated
	// prevents race conditions in later stages of the pipeline
	storedExecutableTypes := msg.NewQueue[[]Event[ebpf.Instrumentable]](
		msg.ChannelBufferLen(pf.cfg.ChannelBufferLen), msg.Name("storedExecutableTypes"))
	swi.Add(ContainerDBUpdaterProvider(pf.ctxInfo.K8sInformer, executableTypes, storedExecutableTypes),
		swarm.WithID("ContainerDBUpdater"))

	swi.Add(traceAttacherProvider(&traceAttacher{
		Cfg:                 pf.cfg,
		OutputTracerEvents:  tracerEvents,
		Metrics:             pf.ctxInfo.Metrics,
		SpanSignalsShortcut: pf.tracesInput,

		InputInstrumentables: storedExecutableTypes,
		EbpfEventContext:     pf.ebpfEventContext,
	}), swarm.WithID("traceAttacher"))

	pipeline, err := swi.Instance(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't instantiate discovery.ProcessFinder pipeline: %w", err)
	}
	tracerEventsCh := tracerEvents.Subscribe(msg.SubscriberName("tracerEventsCh"))
	pipeline.Start(ctx, swarm.WithCancelTimeout(pf.cfg.ShutdownTimeout))
	pf.doneChan = pipeline.Done()
	return tracerEventsCh, nil
}

func (pf *ProcessFinder) Done() <-chan error {
	return pf.doneChan
}

// auxiliary functions to instantiate the go and non-go tracers on diverse steps of the
// discovery pipeline

// the common tracer group should get loaded for any tracer group, only once
func newCommonTracersGroup(cfg *obi.Config) []ebpf.Tracer {
	var tracers []ebpf.Tracer

	// Add tracers based on enabled propagation modes
	// tpinjector handles both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
	if cfg.EBPF.ContextPropagation.HasHeaders() || cfg.EBPF.ContextPropagation.HasTCP() {
		tracers = append(tracers, tpinjector.New(cfg))
	}
	// tctracer handles IP options only (TC egress/ingress)
	if cfg.EBPF.ContextPropagation.HasIPOptions() {
		tracers = append(tracers, tctracer.New(cfg))
	}

	return tracers
}

func newGoTracersGroup(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{gotracer.New(pidFilter, cfg, metrics)}
}

func newGenericTracersGroup(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	if cfg.EBPF.InstrumentGPU {
		return []ebpf.Tracer{generictracer.New(pidFilter, cfg, metrics), gpuevent.New(pidFilter, cfg, metrics)}
	}
	return []ebpf.Tracer{generictracer.New(pidFilter, cfg, metrics)}
}
