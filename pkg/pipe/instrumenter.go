package pipe

import (
	"fmt"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

// builder with injectable instantiators for unit testing
type graphBuilder struct {
	config    *Config
	builder   *graph.Builder
	inspector func(_ goexec.ProcessFinder, funcNames map[string][]string) (goexec.Offsets, error)
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(config *Config) (graph.Graph, error) {
	if err := config.Validate(); err != nil {
		return graph.Graph{}, fmt.Errorf("validating configuration: %w", err)
	}

	return newGraphBuilder(config).buildGraph()
}

// private constructor that can be instantiated from tests to override the node providers
// and offsets inspector
func newGraphBuilder(config *Config) *graphBuilder {
	gb := graph.NewBuilder(node.ChannelBufferLen(config.ChannelBufferLen))
	graph.RegisterCodec(gb, transform.ConvertToSpan)
	graph.RegisterStart(gb, nethttp.EBPFTracerProvider)
	graph.RegisterMiddle(gb, transform.RoutesProvider)
	graph.RegisterTerminal(gb, otel.MetricsReporterProvider)
	graph.RegisterTerminal(gb, otel.TracesReporterProvider)
	graph.RegisterTerminal(gb, debug.NoopNode)
	graph.RegisterTerminal(gb, debug.PrinterNode)

	return &graphBuilder{
		builder:   gb,
		config:    config,
		inspector: goexec.InspectOffsets,
	}
}

func (gb *graphBuilder) buildGraph() (graph.Graph, error) {
	// Build and connect the nodes of the processing pipeline
	//                              +--> TracesSender
	//   httpTracer --> converter --+--> MetricsSender
	//                              +--> PrinterNode

	var finder goexec.ProcessFinder
	if gb.config.EBPF.Port != 0 {
		finder = goexec.OwnedPort(gb.config.EBPF.Port)
	} else {
		finder = goexec.ProcessNamed(gb.config.EBPF.Exec)
	}
	offsets, err := gb.inspector(
		finder,
		map[string][]string{
			nethttp.SectionHTTP:               gb.config.EBPF.Functions,
			nethttp.SectionHTTPBackgroundRead: gb.config.EBPF.HTTPStartBackgroundRead,
			nethttp.SectionGRPCStream:         gb.config.EBPF.GRPCHandleStream,
			nethttp.SectionGRPCStatus:         gb.config.EBPF.GRPCWriteStatus,
			nethttp.SectionRuntimeNewproc1:    gb.config.EBPF.RuntimeNewproc1,
			nethttp.SectionRuntimeGoexit1:     gb.config.EBPF.RuntimeGoexit1,
		},
	)
	if err != nil {
		return graph.Graph{}, fmt.Errorf("error analysing target executable: %w", err)
	}
	gb.config.EBPF.Offsets = &offsets

	if gb.config.Metrics.ServiceName == "" {
		gb.config.Metrics.ServiceName = offsets.FileInfo.CmdExePath
	}
	if gb.config.Traces.ServiceName == "" {
		gb.config.Traces.ServiceName = offsets.FileInfo.CmdExePath
	}

	return gb.builder.Build(gb.config)
}
