package pipe

import (
	"context"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/traces"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/debug"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/prom"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/filter"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/transform"
)

// builder with injectable instantiators for unit testing
type graphFunctions struct {
	config  *beyla.Config
	builder *swarm.Instancer
	ctxInfo *global.ContextInfo
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(
	ctx context.Context,
	config *beyla.Config,
	ctxInfo *global.ContextInfo,
	tracesCh *msg.Queue[[]request.Span],
	processEventsCh *msg.Queue[exec.ProcessEvent],
) (*Instrumenter, error) {
	return newGraphBuilder(config, ctxInfo, tracesCh, processEventsCh).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(
	config *beyla.Config,
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
	// TODO: consider moving the queues to a publis structure so when Beyla is used as library, other components can
	// listen to the messages and expanding the Pipeline
	tracesReaderToRouter := newQueue()
	swi.Add(traces.ReadFromChannel(&traces.ReadDecorator{
		InstanceID:      config.Attributes.InstanceID,
		TracesInput:     tracesCh,
		DecoratedTraces: tracesReaderToRouter,
	}))

	routerToKubeDecorator := newQueue()
	swi.Add(transform.RoutesProvider(
		config.Routes,
		tracesReaderToRouter,
		routerToKubeDecorator,
	))

	kubeDecoratorToNameResolver := newQueue()
	swi.Add(transform.KubeDecoratorProvider(
		ctxInfo, &config.Attributes.Kubernetes,
		routerToKubeDecorator, kubeDecoratorToNameResolver,
	))

	nameResolverToAttrFilter := newQueue()
	swi.Add(transform.NameResolutionProvider(ctxInfo, config.NameResolver,
		kubeDecoratorToNameResolver, nameResolverToAttrFilter))

	// In vendored mode, the invoker might want to override the export queue for connecting their
	// own exporters, otherwise we create a new queue
	exportableSpans := ctxInfo.OverrideAppExportQueue
	if exportableSpans == nil {
		exportableSpans = newQueue()
	}
	swi.Add(filter.ByAttribute(config.Filters.Application, nil, selectorCfg.ExtraGroupAttributesCfg, spanPtrPromGetters,
		nameResolverToAttrFilter, exportableSpans))

	swi.Add(otel.ReportMetrics(
		ctxInfo,
		&config.Metrics,
		selectorCfg,
		exportableSpans,
		processEventsCh,
	))

	swi.Add(otel.TracesReceiver(
		ctxInfo, config.Traces, config.Metrics.SpanMetricsEnabled(), selectorCfg, exportableSpans,
	))
	swi.Add(prom.PrometheusEndpoint(ctxInfo, &config.Prometheus, selectorCfg, exportableSpans, processEventsCh))
	swi.Add(prom.BPFMetrics(ctxInfo, &config.Prometheus))

	swi.Add(debug.PrinterNode(config.TracePrinter, exportableSpans))

	// The returned builder later invokes its "Build" function that, given
	// the contents of the nodesMap struct, will instantiate
	// and interconnect each node according to the SendTo invocations in the
	// Connect() method of the nodesMap.
	return gb
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
