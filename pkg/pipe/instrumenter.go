package pipe

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/prom"
	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

func log() *slog.Logger {
	return slog.With("component", "pipe.Build")
}

// builder with injectable instantiators for unit testing
type graphBuilder struct {
	config  *Config
	builder *graph.Builder
	tracer  *ebpf.ProcessTracer
	ctxInfo *global.ContextInfo
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *Config, tracer *ebpf.ProcessTracer, ctxInfo *global.ContextInfo) (*Instrumenter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(config, tracer, ctxInfo).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(config *Config, tracer *ebpf.ProcessTracer, ctxInfo *global.ContextInfo) *graphBuilder {
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
		tracer:  tracer,
		ctxInfo: ctxInfo,
	}
}

func (gb *graphBuilder) buildGraph(ctx context.Context) (*Instrumenter, error) {
	// setting explicitly some configuration properties that are needed by their
	// respective node providers

	graphDefinition := GraphFromConfig(gb.config, gb.tracer)
	grp, err := gb.builder.Build(ctx, graphDefinition)
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
