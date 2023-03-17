package pipe

import (
	"fmt"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/export/debug"
	otel2 "github.com/grafana/http-autoinstrument/pkg/ebpf/export/otel"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/grafana/http-autoinstrument/pkg/spanner"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"
)

type GraphArch struct {
	EBPF nethttp.EBPFTracer `nodeId:"ebpf" sendsTo:"otel_metrics,otel_traces,print,noop"`

	Metrics otel2.MetricsConfig `nodeId:"otel_metrics"`
	Traces  otel2.TracesConfig  `nodeId:"otel_traces"`
	Printer debug.PrintEnabled  `nodeId:"print"`
	Noop    debug.NoopEnabled   `nodeId:"noop"`
}

// builder with injectable instantiators for unit testing
type graphBuilder struct {
	config    *Config
	builder   *graph.Builder
	inspector func(execFile, funcName string) (goexec.Offsets, error)
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
	graph.RegisterCodec(gb, spanner.ConvertToSpan)
	graph.RegisterStart(gb, nethttp.EBPFTracerProvider)
	graph.RegisterTerminal(gb, otel2.MetricsReporterProvider)
	graph.RegisterTerminal(gb, otel2.TracesReporterProvider)
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

	offsets, err := gb.inspector(gb.config.Exec, gb.config.FuncName)
	if err != nil {
		return graph.Graph{}, fmt.Errorf("error analysing target executable: %w", err)
	}

	return gb.builder.Build(GraphArch{
		EBPF: nethttp.EBPFTracer{Offsets: &offsets},
		Metrics: otel2.MetricsConfig{
			ServiceName:     offsets.FileInfo.CmdExePath,
			Interval:        gb.config.MetricsInterval,
			Endpoint:        gb.config.OTELEndpoint,
			MetricsEndpoint: gb.config.OTELMetricsEndpoint,
		},
		Traces: otel2.TracesConfig{
			ServiceName:    offsets.FileInfo.CmdExePath,
			Endpoint:       gb.config.OTELEndpoint,
			TracesEndpoint: gb.config.OTELTracesEndpoint,
		},
		Printer: debug.PrintEnabled(gb.config.PrintTraces),
		Noop:    debug.NoopEnabled(gb.config.NoopTracer),
	})
}
