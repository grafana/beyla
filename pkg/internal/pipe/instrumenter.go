package pipe

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/export/debug"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/internal/transform"
)

// nodesMap provides the architecture of the whole processing pipeline:
// each node and which nodes are they connected to
type nodesMap struct {
	TracesReader traces.Reader `nodeId:"tracer" sendTo:"routes"`

	// Routes is an optional node. If not set, data will be bypassed to the next stage in the pipeline.
	Routes *transform.RoutesConfig `nodeId:"routes" forwardTo:"kube"`

	// Kubernetes is an optional node. If not set, data will be bypassed to the exporters.
	Kubernetes transform.KubernetesDecorator `nodeId:"kube" forwardTo:"otel_metrics,otel_traces,print,noop,prom"`

	Metrics    otel.MetricsConfig    `nodeId:"otel_metrics"`
	Traces     otel.TracesConfig     `nodeId:"otel_traces"`
	Prometheus prom.PrometheusConfig `nodeId:"prom"`
	Printer    debug.PrintEnabled    `nodeId:"print"`
	Noop       debug.NoopEnabled     `nodeId:"noop"`
}

func configToNodesMap(cfg *Config) *nodesMap {
	return &nodesMap{
		Routes:     cfg.Routes,
		Kubernetes: cfg.Kubernetes,
		Metrics:    cfg.Metrics,
		Traces:     cfg.Traces,
		Prometheus: cfg.Prometheus,
		Printer:    cfg.Printer,
		Noop:       cfg.Noop,
	}
}

// builder with injectable instantiators for unit testing
type graphFunctions struct {
	config  *Config
	builder *graph.Builder
	ctxInfo *global.ContextInfo

	// tracesCh is shared across all the eBPF tracing programs, which send there
	// any discovered trace, and the input node of the graph, which reads and
	// forwards them to the next stages.
	tracesCh <-chan []any
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *Config, ctxInfo *global.ContextInfo, tracesCh <-chan []any) (*Instrumenter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(config, ctxInfo, tracesCh).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(config *Config, ctxInfo *global.ContextInfo, tracesCh <-chan []any) *graphFunctions {
	// This is how the github.com/mariomac/pipes library, works:
	// First, we create a graph builder
	gnb := graph.NewBuilder(node.ChannelBufferLen(config.ChannelBufferLen))
	gb := &graphFunctions{
		builder:  gnb,
		config:   config,
		ctxInfo:  ctxInfo,
		tracesCh: tracesCh,
	}
	// Second, we register providers for each node. Each provider is a function that receives the
	// type of each of the "nodesMap" struct fields, and returns the function that represents
	// each node. Each function will have input and/or output channels.
	graph.RegisterCodec(gnb, transform.ConvertToSpan)
	graph.RegisterStart(gnb, traces.ReaderProvider)
	graph.RegisterMiddle(gnb, transform.RoutesProvider)
	graph.RegisterMiddle(gnb, transform.KubeDecoratorProvider)
	graph.RegisterTerminal(gnb, gb.metricsReporterProvider)
	graph.RegisterTerminal(gnb, gb.tracesReporterProvicer)
	graph.RegisterTerminal(gnb, gb.prometheusProvider)
	graph.RegisterTerminal(gnb, debug.NoopNode)
	graph.RegisterTerminal(gnb, debug.PrinterNode)

	// The returned builder later invokes its "Build" function that, given
	// the contents of the nodesMap struct, will automagically instantiate
	// and interconnect each node according to the "nodeId" and "sendsTo"
	// annotations in the nodesMap struct definition
	return gb
}

func (gb *graphFunctions) buildGraph(ctx context.Context) (*Instrumenter, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers

	definedNodesMap := configToNodesMap(gb.config)
	definedNodesMap.TracesReader.TracesInput = gb.tracesCh
	grp, err := gb.builder.Build(ctx, definedNodesMap)
	if err != nil {
		return nil, err
	}
	return &Instrumenter{
		internalMetrics: gb.ctxInfo.Metrics,
		graph:           &grp,
	}, nil
}

type Instrumenter struct {
	internalMetrics imetrics.Reporter
	graph           *graph.Graph
}

func (i *Instrumenter) Run(ctx context.Context) {
	go i.internalMetrics.Start(ctx)
	i.graph.Run(ctx)
}

// behind this line, adaptors to instantiate the different pipeline nodes according to the expected signature format
// Gocritic is disabled because we need to violate the "hugeParam" check, as the second
// argument in the functions below need to be a value.

//nolint:gocritic
func (gb *graphFunctions) tracesReporterProvicer(ctx context.Context, config otel.TracesConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return otel.ReportTraces(ctx, &config, gb.ctxInfo)
}

//nolint:gocritic
func (gb *graphFunctions) metricsReporterProvider(ctx context.Context, config otel.MetricsConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return otel.ReportMetrics(ctx, &config, gb.ctxInfo)
}

//nolint:gocritic
func (gb *graphFunctions) prometheusProvider(ctx context.Context, config prom.PrometheusConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return prom.PrometheusEndpoint(ctx, &config, gb.ctxInfo)
}
