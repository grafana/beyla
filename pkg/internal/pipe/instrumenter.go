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
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/internal/transform"
)

// nodesMap provides the architecture of the whole processing pipeline:
// each node and which nodes are they connected to
type nodesMap struct {
	TracesReader traces.Reader `sendTo:"Routes"`

	// Routes is an optional node. If not set, data will be bypassed to the next stage in the pipeline.
	Routes *transform.RoutesConfig `forwardTo:"Kubernetes"`

	// Kubernetes is an optional node. If not set, data will be bypassed to the exporters.
	Kubernetes transform.KubernetesDecorator `forwardTo:"Metrics,Traces,Prometheus,Printer,Noop"`

	Metrics    otel.MetricsConfig
	Traces     otel.TracesConfig
	Prometheus prom.PrometheusConfig
	Printer    debug.PrintEnabled
	Noop       debug.NoopEnabled
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
	ctx context.Context

	config  *Config
	builder *graph.Builder
	ctxInfo *global.ContextInfo

	// tracesCh is shared across all the eBPF tracing programs, which send there
	// any discovered trace, and the input node of the graph, which reads and
	// forwards them to the next stages.
	tracesCh <-chan []request.Span
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *Config, ctxInfo *global.ContextInfo, tracesCh <-chan []request.Span) (*Instrumenter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(ctx, config, ctxInfo, tracesCh).buildGraph()
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(ctx context.Context, config *Config, ctxInfo *global.ContextInfo, tracesCh <-chan []request.Span) *graphFunctions {
	// This is how the github.com/mariomac/pipes library, works:
	// https://github.com/mariomac/pipes/tree/main/docs/tutorial/b-highlevel/01-basic-nodes

	// First, we create a graph builder
	gnb := graph.NewBuilder(node.ChannelBufferLen(config.ChannelBufferLen))
	gb := &graphFunctions{
		ctx:      ctx,
		builder:  gnb,
		config:   config,
		ctxInfo:  ctxInfo,
		tracesCh: tracesCh,
	}
	// Second, we register providers for each node. Each provider is a function that receives the
	// type of each of the "nodesMap" struct fields, and returns the function that represents
	// each node. Each function will have input and/or output channels.
	graph.RegisterStart(gnb, gb.tracesListenerProvider)
	graph.RegisterMiddle(gnb, transform.RoutesProvider)
	graph.RegisterMiddle(gnb, transform.KubeDecoratorProvider)
	graph.RegisterTerminal(gnb, gb.metricsReporterProvider)
	graph.RegisterTerminal(gnb, gb.tracesReporterProvicer)
	graph.RegisterTerminal(gnb, gb.prometheusProvider)
	graph.RegisterTerminal(gnb, debug.NoopNode)
	graph.RegisterTerminal(gnb, debug.PrinterNode)

	// The returned builder later invokes its "Build" function that, given
	// the contents of the nodesMap struct, will automagically instantiate
	// and interconnect each node according to the "nodeId" and "sendTo"
	// annotations in the nodesMap struct definition
	return gb
}

func (gb *graphFunctions) buildGraph() (*Instrumenter, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers

	definedNodesMap := configToNodesMap(gb.config)
	definedNodesMap.TracesReader.TracesInput = gb.tracesCh
	grp, err := gb.builder.Build(definedNodesMap)
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
	i.graph.Run()
}

// behind this line, adaptors to instantiate the different pipeline nodes according to the expected signature format
// Gocritic is disabled because we need to violate the "hugeParam" check, as the second
// argument in the functions below need to be a value.

func (gb *graphFunctions) tracesListenerProvider(config traces.Reader) (node.StartFunc[[]request.Span], error) {
	return traces.ReadFromChannel(gb.ctx, config)
}

//nolint:gocritic
func (gb *graphFunctions) tracesReporterProvicer(config otel.TracesConfig) (node.TerminalFunc[[]request.Span], error) {
	return otel.ReportTraces(gb.ctx, &config, gb.ctxInfo)
}

//nolint:gocritic
func (gb *graphFunctions) metricsReporterProvider(config otel.MetricsConfig) (node.TerminalFunc[[]request.Span], error) {
	return otel.ReportMetrics(gb.ctx, &config, gb.ctxInfo)
}

//nolint:gocritic
func (gb *graphFunctions) prometheusProvider(config prom.PrometheusConfig) (node.TerminalFunc[[]request.Span], error) {
	return prom.PrometheusEndpoint(gb.ctx, &config, gb.ctxInfo)
}
