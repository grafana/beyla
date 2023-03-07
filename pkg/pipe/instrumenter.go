package pipe

import (
	"context"
	"fmt"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/grafana/http-autoinstrument/pkg/otel"
	"github.com/grafana/http-autoinstrument/pkg/spanner"

	"github.com/mariomac/pipes/pkg/node"
)

type Graph struct {
	startNode *node.Start[nethttp.HTTPRequestTrace]
}

// builder with injectable instantiators for unit testing
type graphBuilder struct {
	config  *Config
	svcName string

	tracerNode    func(gb *graphBuilder) (*node.Start[nethttp.HTTPRequestTrace], error)
	exporterNodes func(gb *graphBuilder) ([]*node.Terminal[spanner.HTTPRequestSpan], error)
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(config *Config) (Graph, error) {
	if err := config.Validate(); err != nil {
		return Graph{}, fmt.Errorf("validating configuration: %w", err)
	}

	return (&graphBuilder{
		config:        config,
		tracerNode:    ebpfTracerNode,
		exporterNodes: otelExporters,
	}).buildGraph()
}

func (gb *graphBuilder) buildGraph() (Graph, error) {
	// Build and connect the nodes of the processing pipeline
	//                              +--> TracesSender
	//   httpTracer --> converter --+--> MetricsSender
	//                              +--> printerNode
	httpTracer, err := gb.tracerNode(gb)
	if err != nil {
		return Graph{}, err
	}
	exporters, err := gb.exporterNodes(gb)
	if err != nil {
		return Graph{}, err
	}

	converter := node.AsMiddle(spanner.ConvertToSpan)
	httpTracer.SendsTo(converter)
	for _, e := range exporters {
		converter.SendsTo(e)
	}

	return Graph{startNode: httpTracer}, nil
}

// Start the instrumentation --> processing --> submit pipeline
func (p *Graph) Start(ctx context.Context) {
	p.startNode.StartCtx(ctx)
}

// inspects the struct offsets of a given executable, and adds the instrumentation points
func ebpfTracerNode(gb *graphBuilder) (*node.Start[nethttp.HTTPRequestTrace], error) {
	offsetsInfo, err := goexec.InspectOffsets(gb.config.Exec, gb.config.FuncName)
	if err != nil {
		return nil, fmt.Errorf("inspecting executable: %w", err)
	}

	// TODO: allow overriding
	// TODO: when we manage multiple executables form a single instrumenter, this should be set dynamically in the exporters
	gb.svcName = offsetsInfo.FileInfo.CmdExePath

	// Load and instrument the executable file
	instrumentedServe, err := nethttp.Instrument(&offsetsInfo)
	if err != nil {
		return nil, fmt.Errorf("instrumenting executable: %w", err)
	}
	return node.AsStart(instrumentedServe.Run), nil
}

// TODO: allow overriding service name
func otelExporters(gb *graphBuilder) ([]*node.Terminal[spanner.HTTPRequestSpan], error) {
	// for benchmarking, defining NoopTracer disables the rest of exporters
	if gb.config.NoopTracer {
		return []*node.Terminal[spanner.HTTPRequestSpan]{noopNode()}, nil
	}

	var exporters []*node.Terminal[spanner.HTTPRequestSpan]

	tracesEndpoint, metricsEndpoint := gb.config.OTELEndpoint, gb.config.OTELEndpoint

	if gb.config.OTELTracesEndpoint != "" {
		tracesEndpoint = gb.config.OTELTracesEndpoint
	}
	if tracesEndpoint != "" {
		tr, err := otel.NewTracesReporter(gb.svcName, tracesEndpoint)
		if err != nil {
			return nil, fmt.Errorf("starting traces reporter: %w", err)
		}
		exporters = append(exporters, node.AsTerminal(tr.ReportTraces))
	}

	if gb.config.OTELMetricsEndpoint != "" {
		metricsEndpoint = gb.config.OTELMetricsEndpoint
	}
	if metricsEndpoint != "" {
		mr, err := otel.NewMetricsReporter(gb.svcName, metricsEndpoint)
		if err != nil {
			return nil, fmt.Errorf("starting metrics reporter: %w", err)
		}
		exporters = append(exporters, node.AsTerminal(mr.ReportMetrics))
	}

	if gb.config.PrintTraces {
		// Stdout output just for debugging
		exporters = append(exporters, node.AsTerminal(printerNode))
	}
	return exporters, nil
}

func printerNode(spans <-chan spanner.HTTPRequestSpan) {
	for span := range spans {
		fmt.Printf("%s (%s) %v %s %s\n",
			span.Start.Format("2006-01-02 15:04:05.12345"),
			span.End.Sub(span.Start),
			span.Status,
			span.Method,
			span.Path)
	}
}

func noopNode() *node.Terminal[spanner.HTTPRequestSpan] {
	counter := 0
	return node.AsTerminal(func(spans <-chan spanner.HTTPRequestSpan) {
		for range spans {
			counter++
		}
		fmt.Printf("Processed %d requests\n", counter)
	})
}
