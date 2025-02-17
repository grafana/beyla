package pipe

import (
	"context"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/alloy"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/debug"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
	"github.com/grafana/beyla/v2/pkg/internal/filter"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/traces"
	"github.com/grafana/beyla/v2/pkg/transform"
)

// nodesMap provides the architecture of the whole processing pipeline:
// each node and which nodes are they connected to
type nodesMap struct {
	TracesReader pipe.Start[[]request.Span]

	// Routes is an optional pipe. If not enabled, data will be bypassed to the next stage in the pipeline.
	Routes pipe.Middle[[]request.Span, []request.Span]

	// Kubernetes is an optional pipe. If not enabled, data will be bypassed to the exporters.
	Kubernetes pipe.Middle[[]request.Span, []request.Span]

	NameResolver pipe.Middle[[]request.Span, []request.Span]

	AttributeFilter pipe.Middle[[]request.Span, []request.Span]

	AlloyTraces pipe.Final[[]request.Span]
	Metrics     pipe.Final[[]request.Span]
	Traces      pipe.Final[[]request.Span]
	Prometheus  pipe.Final[[]request.Span]
	BpfMetrics  pipe.Final[[]request.Span]
	Printer     pipe.Final[[]request.Span]

	ProcessReport pipe.Final[[]request.Span]
}

// Connect must specify how the above nodes are connected. Nodes that are disabled
// at build time will be Bypassed (e.g. if the Routes node is disabled, the pipes library
// will directly connect TracesReader to Kubernetes node).
func (n *nodesMap) Connect() {
	n.TracesReader.SendTo(n.Routes)
	n.Routes.SendTo(n.Kubernetes)
	n.Kubernetes.SendTo(n.NameResolver)
	n.NameResolver.SendTo(n.AttributeFilter)
	n.AttributeFilter.SendTo(n.AlloyTraces, n.Metrics, n.Traces, n.Prometheus, n.Printer, n.ProcessReport)
}

// accessor functions to each field. Grouped here for code brevity during the pipeline build
func tracesReader(n *nodesMap) *pipe.Start[[]request.Span]                  { return &n.TracesReader }
func router(n *nodesMap) *pipe.Middle[[]request.Span, []request.Span]       { return &n.Routes }
func kubernetes(n *nodesMap) *pipe.Middle[[]request.Span, []request.Span]   { return &n.Kubernetes }
func nameResolver(n *nodesMap) *pipe.Middle[[]request.Span, []request.Span] { return &n.NameResolver }
func attrFilter(n *nodesMap) *pipe.Middle[[]request.Span, []request.Span]   { return &n.AttributeFilter }
func alloyTraces(n *nodesMap) *pipe.Final[[]request.Span]                   { return &n.AlloyTraces }
func otelMetrics(n *nodesMap) *pipe.Final[[]request.Span]                   { return &n.Metrics }
func otelTraces(n *nodesMap) *pipe.Final[[]request.Span]                    { return &n.Traces }
func printer(n *nodesMap) *pipe.Final[[]request.Span]                       { return &n.Printer }
func prometheus(n *nodesMap) *pipe.Final[[]request.Span]                    { return &n.Prometheus }
func bpfMetrics(n *nodesMap) *pipe.Final[[]request.Span]                    { return &n.BpfMetrics }

func processReport(n *nodesMap) *pipe.Final[[]request.Span] { return &n.ProcessReport }

// builder with injectable instantiators for unit testing
type graphFunctions struct {
	config  *beyla.Config
	builder *pipe.Builder[*nodesMap]
	ctxInfo *global.ContextInfo

	// tracesCh is shared across all the eBPF tracing programs, which send there
	// any discovered trace, and the input node of the graph, which reads and
	// forwards them to the next stages.
	tracesCh <-chan []request.Span
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh <-chan []request.Span) (*Instrumenter, error) {
	return newGraphBuilder(ctx, config, ctxInfo, tracesCh).buildGraph()
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh <-chan []request.Span) *graphFunctions {
	// This is how the github.com/mariomac/pipes library, works:
	// https://github.com/mariomac/pipes/tree/main/docs/tutorial/b-highlevel/01-basic-nodes

	// First, we create a graph builder
	gnb := pipe.NewBuilder(&nodesMap{}, pipe.ChannelBufferLen(config.ChannelBufferLen))
	gb := &graphFunctions{
		builder:  gnb,
		config:   config,
		ctxInfo:  ctxInfo,
		tracesCh: tracesCh,
	}
	// Second, we register providers for each pipe node.
	pipe.AddStart(gnb, tracesReader, traces.ReadFromChannel(ctx, &traces.ReadDecorator{
		InstanceID:  config.Attributes.InstanceID,
		TracesInput: gb.tracesCh,
	}))

	pipe.AddMiddleProvider(gnb, router, transform.RoutesProvider(config.Routes))
	pipe.AddMiddleProvider(gnb, kubernetes, transform.KubeDecoratorProvider(ctx, &config.Attributes.Kubernetes, ctxInfo))
	pipe.AddMiddleProvider(gnb, nameResolver, transform.NameResolutionProvider(ctx, gb.ctxInfo, config.NameResolver))
	pipe.AddMiddleProvider(gnb, attrFilter, filter.ByAttribute(config.Filters.Application, spanPtrPromGetters))
	config.Metrics.Grafana = &gb.config.Grafana.OTLP
	pipe.AddFinalProvider(gnb, otelMetrics, otel.ReportMetrics(ctx, gb.ctxInfo, &config.Metrics, config.Attributes.Select))
	config.Traces.Grafana = &gb.config.Grafana.OTLP
	pipe.AddFinalProvider(gnb, otelTraces, otel.TracesReceiver(ctx, config.Traces, gb.ctxInfo, config.Attributes.Select))
	pipe.AddFinalProvider(gnb, prometheus, prom.PrometheusEndpoint(ctx, gb.ctxInfo, &config.Prometheus, config.Attributes.Select))
	pipe.AddFinalProvider(gnb, bpfMetrics, prom.BPFMetrics(ctx, gb.ctxInfo, &config.Prometheus))
	pipe.AddFinalProvider(gnb, alloyTraces, alloy.TracesReceiver(ctx, gb.ctxInfo, &config.TracesReceiver, config.Attributes.Select))

	pipe.AddFinalProvider(gnb, printer, debug.PrinterNode(config.TracePrinter))

	// process subpipeline will start another pipeline only to collect and export data
	// about the processes of an instrumented application
	pipe.AddFinalProvider(gnb, processReport, SubPipelineProvider(ctx, ctxInfo, config))

	// The returned builder later invokes its "Build" function that, given
	// the contents of the nodesMap struct, will instantiate
	// and interconnect each node according to the SendTo invocations in the
	// Connect() method of the nodesMap.
	return gb
}

func (gb *graphFunctions) buildGraph() (*Instrumenter, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers

	grp, err := gb.builder.Build()
	if err != nil {
		return nil, err
	}
	return &Instrumenter{
		internalMetrics: gb.ctxInfo.Metrics,
		graph:           grp,
	}, nil
}

type Instrumenter struct {
	internalMetrics imetrics.Reporter
	graph           *pipe.Runner
}

func (i *Instrumenter) Run(ctx context.Context) {
	go i.internalMetrics.Start(ctx)
	i.graph.Start()
	// run until either the graph is finished or the context is cancelled
	select {
	case <-i.graph.Done():
	case <-ctx.Done():
	}
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
