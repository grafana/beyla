package pipe

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/prom"
	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

// builder with injectable instantiators for unit testing
type graphBuilder struct {
	config  *Config
	builder *graph.Builder
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *Config) (graph.Graph, error) {
	if err := config.Validate(); err != nil {
		return graph.Graph{}, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(config).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(config *Config) *graphBuilder {
	gb := graph.NewBuilder(node.ChannelBufferLen(config.ChannelBufferLen))
	graph.RegisterCodec(gb, transform.ConvertToSpan)
	graph.RegisterMultiStart(gb, ebpf.TracerProvider)
	graph.RegisterMiddle(gb, transform.RoutesProvider)
	graph.RegisterTerminal(gb, otel.MetricsReporterProvider)
	graph.RegisterTerminal(gb, otel.TracesReporterProvider)
	graph.RegisterTerminal(gb, prom.PrometheusEndpointProvider)
	graph.RegisterTerminal(gb, debug.NoopNode)
	graph.RegisterTerminal(gb, debug.PrinterNode)

	return &graphBuilder{
		builder: gb,
		config:  config,
	}
}

func (gb *graphBuilder) buildGraph(ctx context.Context) (graph.Graph, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers
	ctxInfo := &global.ContextInfo{
		ReportRoutes: gb.config.Routes != nil,
	}
	setMetricsReporter(ctxInfo, &gb.config.InternalMetrics)
	ctx = global.SetContext(ctx, ctxInfo)
	return gb.builder.Build(ctx, gb.config)
}

type Instrumenter struct {
	internalMetrics imetrics.Reporter
	graph           *graph.Graph
}

func (i *Instrumenter) Start(ctx context.Context) {
	go i.internalMetrics.Start(ctx)
	i.graph.Run(ctx)
}

// SetReporter populates the global context info with an internal metrics reporter according to the passed config.
func setMetricsReporter(ctx *global.ContextInfo, cfg *imetrics.Config) {
	if cfg.Prometheus.Port != 0 {
		ctx.Metrics = imetrics.NewPrometheusReporter(&cfg.Prometheus, &ctx.Prometheus)
	} else {
		ctx.Metrics = &imetrics.NoopReporter{}
	}
}
