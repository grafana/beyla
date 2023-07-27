package pipe

import (
	"context"
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/export/prom"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/transform"
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
func Build(ctx context.Context, config *Config, ctxInfo *global.ContextInfo, tracer *ebpf.ProcessTracer) (*Instrumenter, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(config, ctxInfo, tracer).buildGraph(ctx)
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(config *Config, ctxInfo *global.ContextInfo, tracer *ebpf.ProcessTracer) *graphBuilder {
	gnb := graph.NewBuilder(node.ChannelBufferLen(config.ChannelBufferLen))
	gb := &graphBuilder{
		builder: gnb,
		config:  config,
		tracer:  tracer,
		ctxInfo: ctxInfo,
	}
	graph.RegisterCodec(gnb, transform.ConvertToSpan)
	graph.RegisterMultiStart(gnb, ebpf.TracerProvider)
	graph.RegisterMiddle(gnb, transform.RoutesProvider)
	graph.RegisterTerminal(gnb, gb.metricsReporterProvider)
	graph.RegisterTerminal(gnb, gb.tracesReporterProvicer)
	graph.RegisterTerminal(gnb, gb.prometheusProvider)
	graph.RegisterTerminal(gnb, debug.NoopNode)
	graph.RegisterTerminal(gnb, debug.PrinterNode)

	return gb
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

// behind this line, adaptors to instantiate the different pipeline nodes according to the expected signature format

func (gb *graphBuilder) tracesReporterProvicer(ctx context.Context, config otel.TracesConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return otel.ReportTraces(ctx, &config, gb.ctxInfo)
}

func (gb *graphBuilder) metricsReporterProvider(ctx context.Context, config otel.MetricsConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return otel.ReportMetrics(ctx, &config, gb.ctxInfo)
}

func (gb *graphBuilder) prometheusProvider(ctx context.Context, config prom.PrometheusConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	return prom.PrometheusEndpoint(ctx, &config, gb.ctxInfo)
}
