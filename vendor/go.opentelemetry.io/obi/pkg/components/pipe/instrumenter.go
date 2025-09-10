// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pipe

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/imetrics"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/traces"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
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

	newQueue := func() *msg.Queue[[]request.Span] {
		return msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))
	}

	// Second, we register instancers for each pipe node, as well as communication queues between them
	// TODO: consider moving the queues to a public structure so when OBI is used as library, other components can
	// listen to the messages and expanding the Pipeline
	tracesReaderToRouter := newQueue()
	swi.Add(traces.ReadFromChannel(&traces.ReadDecorator{
		InstanceID:      config.Attributes.InstanceID,
		TracesInput:     tracesCh,
		DecoratedTraces: tracesReaderToRouter,
	}), swarm.WithID("ReadFromChannel"))

	routerToKubeDecorator := newQueue()
	swi.Add(transform.RoutesProvider(
		config.Routes,
		tracesReaderToRouter,
		routerToKubeDecorator,
	), swarm.WithID("Routes"))

	kubeDecoratorToNameResolver := newQueue()
	swi.Add(transform.KubeDecoratorProvider(
		ctxInfo, &config.Attributes.Kubernetes,
		routerToKubeDecorator, kubeDecoratorToNameResolver,
	), swarm.WithID("KubeDecorator"))

	nameResolverToAttrFilter := newQueue()
	swi.Add(transform.NameResolutionProvider(ctxInfo, config.NameResolver,
		kubeDecoratorToNameResolver, nameResolverToAttrFilter),
		swarm.WithID("NameResolution"))

	// In vendored mode, the invoker might want to override the export queue for connecting their
	// own exporters, otherwise we create a new queue
	exportableSpans := ctxInfo.OverrideAppExportQueue
	if exportableSpans == nil {
		exportableSpans = newQueue()
	}
	swi.Add(filter.ByAttribute(config.Filters.Application, nil, selectorCfg.ExtraGroupAttributesCfg, spanPtrPromGetters,
		nameResolverToAttrFilter, exportableSpans),
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
	newQueue := func() *msg.Queue[[]request.Span] {
		return msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))
	}

	// since this sub pipeline might modify the traces that are going to be exported as metrics,
	// but we don't want to modify their values when exported as traces in the other
	// sup-pipeline, we create a node that just copies the spans array
	// This queue also prevents that exportableSpans queue is both read from the
	// trace exporters and Bypassed by IPSFilter or SpanNameLimiter nodes, which
	// might lead to get it blocked.
	copiedSpans := newQueue()
	inputCh := exportableSpans.Subscribe()
	swi.Add(swarm.DirectInstance(cloneSpans(inputCh, copiedSpans)))

	ipDroppedMetrics := newQueue()
	swi.Add(transform.IPsFilter(
		config.Attributes.DropMetricsUnresolvedIPs,
		copiedSpans,
		ipDroppedMetrics,
	), swarm.WithID("IPsFilter"))

	spanNameAggregatedMetrics := newQueue()
	swi.Add(transform.SpanNameLimiter(transform.SpanNameLimiterConfig{
		Limit: config.Attributes.MetricSpanNameAggregationLimit,
		OTEL:  &config.Metrics,
		Prom:  &config.Prometheus,
	}, ipDroppedMetrics, spanNameAggregatedMetrics))

	swi.Add(otel.ReportMetrics(
		ctxInfo,
		&config.Metrics,
		selectorCfg,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("OTELMetricsExport"))

	swi.Add(otel.ReportSvcGraphMetrics(
		ctxInfo,
		&config.Metrics,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("OTELSvcGraphMetricsExport"))

	swi.Add(prom.PrometheusEndpoint(
		ctxInfo,
		&config.Prometheus,
		selectorCfg,
		spanNameAggregatedMetrics,
		processEventsCh,
	), swarm.WithID("PrometheusEndpoint"))
}

func cloneSpans(inputCh <-chan []request.Span, output *msg.Queue[[]request.Span]) func(ctx context.Context) {
	return func(ctx context.Context) {
		defer output.Close()
		log := slog.With("component", "SpanCloner")
		log.Info("starting span cloner")
		for {
			select {
			case <-ctx.Done():
				log.Info("context done. terminating span cloner")
				return
			case spans := <-inputCh:
				spansCopy := make([]request.Span, len(spans))
				cpy := copy(spansCopy, spans)
				output.Send(spansCopy[:cpy])
			}
		}
	}
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

// spanPtrPromGetters adapts the invocation of SpanPromGetters to work with a request.Span value
// instead of a *request.Span pointer. This is a convenience method created to avoid having to
// rewrite the pipeline types from []request.Span types to []*request.Span
func spanPtrPromGetters(name attr.Name) (attributes.Getter[request.Span, string], bool) {
	if ptrGetter, ok := request.SpanPromGetters(name); ok {
		return func(span request.Span) string { return ptrGetter(&span) }, true
	}
	return nil, false
}
