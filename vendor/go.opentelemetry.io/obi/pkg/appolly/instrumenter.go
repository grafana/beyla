// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/internal/traces"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/transform"
)

// builder with injectable instantiators for unit testing
type graphFunctions struct {
	config  *obi.Config
	builder *swarm.Instancer
	ctxInfo *global.ContextInfo
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(
	ctx context.Context,
	config *obi.Config,
	ctxInfo *global.ContextInfo,
	tracesCh *msg.Queue[[]request.Span],
	processEventsCh *msg.Queue[exec.ProcessEvent],
) (*Instrumenter, error) {
	return newGraphBuilder(config, ctxInfo, tracesCh, processEventsCh).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(
	config *obi.Config,
	ctxInfo *global.ContextInfo,
	tracesCh *msg.Queue[[]request.Span],
	processEventsCh *msg.Queue[exec.ProcessEvent],
) *graphFunctions {
	// First, we create a graph builder
	swi := &swarm.Instancer{}
	gb := &graphFunctions{
		builder: swi,
		config:  config,
		ctxInfo: ctxInfo,
	}

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            config.Attributes.Select,
		ExtraGroupAttributesCfg: config.Attributes.ExtraGroupAttributes,
	}

	newQueue := func(name string) *msg.Queue[[]request.Span] {
		return msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen), msg.Name(name))
	}

	// Second, we register instancers for each pipe node, as well as communication queues between them
	// TODO: consider moving the queues to a public structure so when OBI is used as library, other components can
	// listen to the messages and expanding the Pipeline
	tracesReaderToRouter := newQueue("tracesReaderToRouter")
	swi.Add(traces.ReadFromChannel(&traces.ReadDecorator{
		InstanceID:      config.Attributes.InstanceID,
		TracesInput:     tracesCh,
		DecoratedTraces: tracesReaderToRouter,
	}), swarm.WithID("ReadFromChannel"))

	routerToKubeDecorator := msg.NewQueue[[]request.Span](
		msg.ChannelBufferLen(config.ChannelBufferLen),
		msg.Name("routerToKubeDecorator"),
		// make sure that we are able to wait for the informer sync timeout before failing the pipeline
		// if a message gets bocked while the Kube decorator starts
		msg.SendTimeout(config.Attributes.Kubernetes.InformersSyncTimeout+20*time.Second))
	swi.Add(transform.RoutesProvider(
		config.Routes,
		tracesReaderToRouter,
		routerToKubeDecorator,
	), swarm.WithID("Routes"))

	kubeDecoratorToNameResolver := newQueue("kubeDecoratorToNameResolver")
	swi.Add(transform.KubeDecoratorProvider(
		ctxInfo, &config.Attributes.Kubernetes,
		routerToKubeDecorator, kubeDecoratorToNameResolver,
	), swarm.WithID("KubeDecorator"))

	nameResolverToAttrFilter := newQueue("nameResolverToAttrFilter")
	swi.Add(transform.NameResolutionProvider(ctxInfo, config.NameResolver,
		kubeDecoratorToNameResolver, nameResolverToAttrFilter),
		swarm.WithID("NameResolution"))

	// In vendored mode, the invoker might want to override the export queue for connecting their
	// own exporters, otherwise we create a new queue
	exportableSpans := ctxInfo.OverrideAppExportQueue
	if exportableSpans == nil {
		exportableSpans = newQueue("exportableSpans")
	}
	swi.Add(filter.ByAttribute(config.Filters.Application,
		nil,
		selectorCfg.ExtraGroupAttributesCfg,
		spanPtrPromGetters(config),
		nameResolverToAttrFilter,
		exportableSpans),
		swarm.WithID("AttributesFilter"))

	swi.Add(otel.TracesReceiver(
		ctxInfo, config.Traces, config.SpanMetricsEnabledForTraces(), selectorCfg, exportableSpans,
	), swarm.WithID("OTELTracesReceiver"))
	swi.Add(debug.PrinterNode(config.TracePrinter, exportableSpans),
		swarm.WithID("PrinterNode"))

	// some nodes (ipNodesFilter, span name limiter...) are only passed to the metrics export nodes.
	// Nodes directly handling raw traces will still get the unfiltered exportableSpans queue.
	// If no metrics exporter is configured, we will not start the metrics subpipeline to save resources.
	exportingMetrics := config.Metrics.Enabled() ||
		config.Metrics.ServiceGraphMetricsEnabled() ||
		config.Prometheus.Enabled()
	if exportingMetrics {
		setupMetricsSubPipeline(config, ctxInfo, swi, exportableSpans, selectorCfg, processEventsCh)
	}

	swi.Add(prom.BPFMetrics(ctxInfo, &config.Prometheus),
		swarm.WithID("BPFMetrics"))

	// The returned builder later invokes its "Build" function that, given
	// the contents of the nodesMap struct, will instantiate
	// and interconnect each node according to the SendTo invocations in the
	// Connect() method of the nodesMap.
	return gb
}

func setupMetricsSubPipeline(
	config *obi.Config,
	ctxInfo *global.ContextInfo,
	swi *swarm.Instancer,
	exportableSpans *msg.Queue[[]request.Span],
	selectorCfg *attributes.SelectorConfig,
	processEventsCh *msg.Queue[exec.ProcessEvent],
) {
	newQueue := func(name string) *msg.Queue[[]request.Span] {
		return msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen), msg.Name(name))
	}

	spanNameAggregatedMetrics := newQueue("spanNameAggregatedMetrics")
	swi.Add(transform.SpanNameLimiter(transform.SpanNameLimiterConfig{
		Limit: config.Attributes.MetricSpanNameAggregationLimit,
		OTEL:  &config.Metrics,
		Prom:  &config.Prometheus,
	}, exportableSpans, spanNameAggregatedMetrics))

	unresolvedCfg := request.UnresolvedNames{
		Generic:  config.Attributes.RenameUnresolvedHosts,
		Outgoing: config.Attributes.RenameUnresolvedHostsOutgoing,
		Incoming: config.Attributes.RenameUnresolvedHostsIncoming,
	}

	swi.Add(otel.ReportMetrics(
		ctxInfo,
		&config.Metrics,
		selectorCfg,
		unresolvedCfg,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("OTELMetricsExport"))

	swi.Add(otel.ReportSvcGraphMetrics(
		ctxInfo,
		&config.Metrics,
		unresolvedCfg,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("OTELSvcGraphMetricsExport"))

	swi.Add(prom.PrometheusEndpoint(
		ctxInfo,
		&config.Prometheus,
		selectorCfg,
		unresolvedCfg,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("PrometheusEndpoint"))
}

func (gb *graphFunctions) buildGraph(ctx context.Context) (*Instrumenter, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers

	grp, err := gb.builder.Instance(ctx)
	if err != nil {
		return nil, err
	}
	return &Instrumenter{
		internalMetrics: gb.ctxInfo.Metrics,
		graph:           grp,
		cancelTimeout:   gb.config.ShutdownTimeout,
	}, nil
}

type Instrumenter struct {
	internalMetrics imetrics.Reporter
	cancelTimeout   time.Duration
	graph           *swarm.Runner
}

func (i *Instrumenter) Start(ctx context.Context) <-chan error {
	go i.internalMetrics.Start(ctx)
	i.graph.Start(ctx, swarm.WithCancelTimeout(i.cancelTimeout))
	return i.graph.Done()
}

// spanPtrPromGetters adapts the invocation of spanPromGetters to work with a request.Span value
// instead of a *request.Span pointer. This is a convenience method created to avoid having to
// rewrite the pipeline types from []request.Span types to []*request.Span
func spanPtrPromGetters(cfg *obi.Config) attributes.NamedGetters[request.Span, string] {
	unresolvedCfg := request.UnresolvedNames{
		Generic:  cfg.Attributes.RenameUnresolvedHosts,
		Outgoing: cfg.Attributes.RenameUnresolvedHostsOutgoing,
		Incoming: cfg.Attributes.RenameUnresolvedHostsIncoming,
	}

	getter := request.SpanPromGetters(unresolvedCfg)
	return func(name attr.Name) (attributes.Getter[request.Span, string], bool) {
		if ptrGetter, ok := getter(name); ok {
			return func(span request.Span) string { return ptrGetter(&span) }, true
		}
		return nil, false
	}
}
