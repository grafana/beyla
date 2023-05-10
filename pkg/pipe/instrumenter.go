package pipe

import (
	"context"
	"fmt"
	"strings"

	"github.com/grafana/ebpf-autoinstrument/pkg/export/prom"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
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

func programName(path string) string {
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}

func (gb *graphBuilder) buildGraph(ctx context.Context) (graph.Graph, error) {
	// setting manually some configuration properties that are needed by their
	// respective node providers
	if gb.config.Prometheus.Enabled() {
		// Prometheus will report routes as attributes if the Routes node is configured
		ctx = context.WithValue(ctx, prom.ReportRoutesCtxKey, gb.config.Routes != nil) //nolint:staticcheck
	}
	gb.config.EBPF.OnOffsets = func(offsets *goexec.Offsets) {
		if gb.config.Metrics.ServiceName == "" {
			gb.config.Metrics.ServiceName = programName(offsets.FileInfo.CmdExePath)
		}
		if gb.config.Traces.ServiceName == "" {
			gb.config.Traces.ServiceName = programName(offsets.FileInfo.CmdExePath)
		}
	}

	return gb.builder.Build(ctx, gb.config)
}
