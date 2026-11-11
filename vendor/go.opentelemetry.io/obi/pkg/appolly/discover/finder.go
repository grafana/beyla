// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"
	msgh "go.opentelemetry.io/obi/pkg/internal/helpers/msg"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/liveprober"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type ProcessFinder struct {
	cfg              *obi.Config
	ctxInfo          *global.ContextInfo
	tracesInput      *msg.Queue[[]request.Span]
	runtimeMetrics   *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]
	ebpfEventContext *ebpfcommon.EBPFEventContext
	doneChan         <-chan error
}

func NewProcessFinder(
	cfg *obi.Config,
	ctxInfo *global.ContextInfo,
	tracesInput *msg.Queue[[]request.Span],
	runtimeMetrics *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
	ebpfEventContext *ebpfcommon.EBPFEventContext,
) *ProcessFinder {
	return &ProcessFinder{
		cfg:              cfg,
		ctxInfo:          ctxInfo,
		tracesInput:      tracesInput,
		runtimeMetrics:   runtimeMetrics,
		ebpfEventContext: ebpfEventContext,
	}
}

type processFinderStartConfig struct {
	enrichedProcessEvents *msg.Queue[[]Event[ProcessAttrs]]
	dynamicPIDSelector    *DynamicPIDSelector
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

// WithDynamicPIDSelector supplies the OBI dynamic PID set. Caller can pass discover.NewDynamicPIDSelector()
// and add PIDs via the selector. When non-nil, the finder wires it to the matcher and removed-PID
// notifications are used for synthetic deletes.
func WithDynamicPIDSelector(selector *DynamicPIDSelector) ProcessFinderStartOpt {
	return func(cfg *processFinderStartConfig) {
		cfg.dynamicPIDSelector = selector
	}
}

// Start the ProcessFinder pipeline in background. It returns a channel where each new discovered
// ebpf.ProcessTracer will be notified.
func (pf *ProcessFinder) Start(ctx context.Context, opts ...ProcessFinderStartOpt) (<-chan Event[*ebpf.Instrumentable], error) {
	startConfig := processFinderStartConfig{}
	for _, opt := range opts {
		opt(&startConfig)
	}

	var dynamic *liveprober.Manager
	var javaDynamic *javaagent.DynamicRegistry
	var nodeDynamic *nodejs.DynamicRegistry
	if pf.cfg.DynamicInstrumentation.IsEnabled() {
		if startConfig.dynamicPIDSelector != nil {
			return nil, errors.New("dynamic instrumentation rules cannot be combined with an embedding application's dynamic PID selector")
		}
		dynamic = liveprober.New()
		javaDynamic = javaagent.NewDynamicRegistry(ctx, pf.cfg.DynamicInstrumentation, pf.ebpfEventContext)
		nodeDynamic = nodejs.NewDynamicRegistry(ctx, pf.cfg.DynamicInstrumentation, pf.ebpfEventContext)
		dynamic.Configure(pf.cfg.DynamicInstrumentation, ebpf.NewSymbolCache(pf.cfg.DynamicInstrumentation), pf.ctxInfo.Metrics)
		pf.ebpfEventContext.ServiceMetadataUpdated = func(pid app.PID, service svc.Attrs) {
			dynamic.SetService(int(pid), service)
		}
		if err := dynamic.Run(ctx, pf.cfg.DynamicInstrumentation, pf.cfg.DynamicInstrumentationConfigPath); err != nil {
			return nil, err
		}
	}
	tracerEvents := msgh.QueueFromConfig[Event[*ebpf.Instrumentable]](pf.cfg, pf.ctxInfo.Metrics, "tracerEvents")

	logDeprecationAndConflicts(pf.cfg)
	configCriteria := FindingCriteria(pf.cfg)
	var appDynamicSelector *dynamicPIDSignalView
	if startConfig.dynamicPIDSelector != nil {
		appDynamicSelector = startConfig.dynamicPIDSelector.appSignals()
	}

	swi := swarm.Instancer{}
	processEvents := msgh.QueueFromConfig[[]Event[ProcessAttrs]](pf.cfg, pf.ctxInfo.Metrics, "processEvents")

	var addedPIDsCh <-chan []app.PID
	if appDynamicSelector != nil {
		addedPIDsCh = appDynamicSelector.AddedPIDsNotifyContext(ctx)
	}
	watchCriteria := configCriteria
	if dynamic != nil {
		var ports services.IntEnum
		_ = ports.UnmarshalText([]byte("1-65535"))
		watchCriteria = append(append([]services.Selector{}, configCriteria...), &services.GlobAttributes{OpenPorts: ports})
	}
	swi.Add(swarm.DirectInstance(ProcessWatcherFunc(pf.cfg, pf.ebpfEventContext, processEvents, watchCriteria, addedPIDsCh)),
		swarm.WithID("ProcessWatcher"))

	kubeEnrichedEvents := msgh.QueueFromConfig[[]Event[ProcessAttrs]](pf.cfg, pf.ctxInfo.Metrics, "kubeEnrichedEvents")
	swi.Add(WatcherKubeEnricherProvider(pf.ctxInfo.K8sInformer, processEvents, kubeEnrichedEvents),
		swarm.WithID("WatcherKubeEnricher"))

	enrichedProcessEvents := startConfig.enrichedProcessEvents
	if enrichedProcessEvents == nil {
		enrichedProcessEvents = msgh.QueueFromConfig[[]Event[ProcessAttrs]](pf.cfg, pf.ctxInfo.Metrics, "enrichedProcessEvents")
	}
	swi.Add(DockerDiscoveryDecoratorProvider(
		pf.ctxInfo.K8sInformer,
		pf.ctxInfo.DockerMetadata,
		kubeEnrichedEvents,
		enrichedProcessEvents,
	), swarm.WithID("DockerDiscoveryDecoratorProvider"))

	langEnrichedEvents := msgh.QueueFromConfig[[]Event[ProcessAttrs]](pf.cfg, pf.ctxInfo.Metrics, "languageEnrichedEvents")
	swi.Add(LanguageDecoratorProvider(
		pf.cfg,
		enrichedProcessEvents,
		langEnrichedEvents,
	), swarm.WithID("LanguageDecoratorProvider"))

	var kubeStore *kube.Store
	if pf.ctxInfo.K8sInformer.IsKubeEnabled() {
		var err error
		kubeStore, err = pf.ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, err
		}
	}
	criteriaFilteredEvents := msgh.QueueFromConfig[[]Event[ProcessMatch]](pf.cfg, pf.ctxInfo.Metrics, "criteriaFilteredEvents")
	swi.Add(criteriaMatcherProvider(pf.cfg, langEnrichedEvents, criteriaFilteredEvents, configCriteria, startConfig.dynamicPIDSelector, matcherContext{dynamic: dynamic, store: kubeStore}),
		swarm.WithID("CriteriaMatcher"))
	swi.Add(dynamicMatcherProvider(langEnrichedEvents, criteriaFilteredEvents, appDynamicSelector),
		swarm.WithID("DynamicMatcher"))

	executableTypes := msgh.QueueFromConfig[[]Event[ebpf.Instrumentable]](pf.cfg, pf.ctxInfo.Metrics, "executableTypes")
	swi.Add(ExecTyperProvider(pf.cfg, pf.ctxInfo.Metrics, pf.ctxInfo.K8sInformer, criteriaFilteredEvents, executableTypes),
		swarm.WithID("ExecTyper"))

	processContextEnrichedTypes := msgh.QueueFromConfig[[]Event[ebpf.Instrumentable]](pf.cfg, pf.ctxInfo.Metrics, "processContextEnrichedTypes")
	swi.Add(ProcessContextDecoratorProvider(pf.cfg.Discovery.ProcessContextPollInterval, executableTypes, processContextEnrichedTypes),
		swarm.WithID("ProcessContextDecorator"))

	// we could subscribe ContainerStoreUpdater directly to the executableTypes queue and not providing any output channel
	// but forcing the output by the executableTypesReplica channel only after the Container DB has been updated
	// prevents race conditions in later stages of the pipeline
	storedExecutableTypes := msgh.QueueFromConfig[[]Event[ebpf.Instrumentable]](pf.cfg, pf.ctxInfo.Metrics, "storedExecutableTypes")
	swi.Add(ContainerStoreUpdaterProvider(pf.ctxInfo.K8sInformer, processContextEnrichedTypes, storedExecutableTypes),
		swarm.WithID("ContainerStoreUpdater"))
	swi.Add(traceAttacherProvider(&traceAttacher{
		Cfg:                    pf.cfg,
		OutputTracerEvents:     tracerEvents,
		Metrics:                pf.ctxInfo.Metrics,
		SpanSignalsShortcut:    pf.tracesInput,
		RuntimeMetrics:         pf.runtimeMetrics,
		DynamicPIDSelector:     startConfig.dynamicPIDSelector,
		DynamicInstrumentation: dynamic,
		JavaDynamic:            javaDynamic,
		NodeDynamic:            nodeDynamic,

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
func newCommonTracersGroup(cfg *obi.Config, metrics imetrics.Reporter, pidFilter ebpfcommon.ServiceFilter) []ebpf.Tracer {
	var tracers []ebpf.Tracer

	// Add tracers based on configuration

	// Enables tpinjector which handles context propagation via both HTTP headers (sk_msg) and TCP options (BPF_SOCK_OPS)
	if cfg.EBPF.ContextPropagation.HasHeaders() || cfg.EBPF.ContextPropagation.HasTCP() {
		tracers = append(tracers, tpinjector.New(cfg))
	}

	// Enables log enricher which handles trace-log correlation
	if cfg.EBPF.LogEnricher.Enabled() {
		logEnricher := logenricher.New(cfg)
		if logEnricher != nil {
			tracers = append(tracers, logEnricher)
		}
	}

	// Enables GPU tracer
	if cfg.EBPF.CudaInstrumentationEnabled() {
		tracers = append(tracers, gpuevent.New(pidFilter, cfg, metrics))
	}

	return tracers
}

func newGoTracersGroup(
	pidFilter ebpfcommon.ServiceFilter,
	cfg *obi.Config,
	metrics imetrics.Reporter,
) []ebpf.Tracer {
	return []ebpf.Tracer{gotracer.New(pidFilter, cfg, metrics)}
}

func newGenericTracersGroup(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) []ebpf.Tracer {
	return []ebpf.Tracer{generictracer.New(pidFilter, cfg, metrics)}
}
