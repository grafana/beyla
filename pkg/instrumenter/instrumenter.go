package instrumenter

import (
	"fmt"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/goexec"
	"github.com/grafana/http-autoinstrument/pkg/otel"
	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
)

type Pipeline struct {
	startNode *node.Start[nethttp.HttpRequestTrace]
}

// BuildPipeline instantiates the whole instrumentation --> processing --> submit
// pipeline and returns it as a startable item
func BuildPipeline(config Config) (Pipeline, error) {

	offsetsInfo, err := goexec.InspectOffsets(config.Exec, config.FuncName)
	if err != nil {
		return Pipeline{}, fmt.Errorf("inspecting executable: %w", err)
	}

	// Load and instrument the executable file
	instrumetedServe, err := nethttp.Instrument(offsetsInfo)
	if err != nil {
		return Pipeline{}, fmt.Errorf("instrumenting executable: %w", err)
	}

	// Build and connect the nodes of the processing pipeline
	httpTracer := node.AsStart(instrumetedServe.Run)
	converter := node.AsMiddle(spanner.ConvertToSpan)
	httpTracer.SendsTo(converter)

	// TODO: allow overriding service name
	tracesEndpoint, metricsEndpoint := config.OTELEndpoint, config.OTELEndpoint
	if config.OTELTracesEndpoint != "" {
		tracesEndpoint = config.OTELTracesEndpoint
	}
	if config.OTELMetricsEndpoint != "" {
		metricsEndpoint = config.OTELMetricsEndpoint
	}
	reporter := otel.NewReporter(
		offsetsInfo.FileInfo.CmdExePath, tracesEndpoint, metricsEndpoint)
	if err := reporter.Start(); err != nil {
		return Pipeline{}, fmt.Errorf("starting OTEL reporter: %w", err)
	}

	outNodes := 0
	if tracesEndpoint != "" {
		outNodes++
		converter.SendsTo(node.AsTerminal(reporter.ReportTraces))
	}

	if metricsEndpoint != "" {
		outNodes++
		converter.SendsTo(node.AsTerminal(reporter.ReportMetrics))
	}

	if config.PrintTraces {
		outNodes++
		// Stdout output just for debugging
		converter.SendsTo(printerNode())
	}

	// TODO: instead of checking here, do a previous configuration check we can assume this
	// is correct
	if outNodes == 0 {
		return Pipeline{}, fmt.Errorf("you should define at least one of OTEL_EXPORTER_OTLP_ENDPOINT or PRINT_TRACES")
	}

	return Pipeline{startNode: httpTracer}, nil
}

// Start the instrumentation --> processing --> submit pipeline
func (p *Pipeline) Start() {
	p.startNode.Start()
}

func printerNode() *node.Terminal[spanner.HttpRequestSpan] {
	return node.AsTerminal(func(spans <-chan spanner.HttpRequestSpan) {
		for span := range spans {
			fmt.Printf("%s (%s) %v %s %s\n",
				span.Start.Format("2006-01-02 15:04:05.12345"),
				span.End.Sub(span.Start),
				span.Status,
				span.Method,
				span.Path)
		}
	})
}
