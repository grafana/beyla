package instrumenter

import (
	"fmt"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/exec"
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
	// Analyse executable ELF file and find instrumentation points
	processPath, processElf, err := exec.FindExecELF(config.Exec)
	if err != nil {
		return Pipeline{}, fmt.Errorf("looking for executable ELF: %w", err)
	}
	defer processElf.Close()
	offsets, err := exec.GoInstrumentationPoints(processElf, config.FuncName)
	if err != nil {
		return Pipeline{}, fmt.Errorf("searching for instrumentation points: %w", err)
	}

	// Load and instrument the executable file
	instrumetedServe, err := nethttp.Instrument(processPath, offsets)
	if err != nil {
		return Pipeline{}, fmt.Errorf("instrumenting executable: %w", err)
	}

	// Build and connect the nodes of the processing pipeline
	httpTracer := node.AsStart(instrumetedServe.Run)
	converter := node.AsMiddle(spanner.ConvertToSpan)
	httpTracer.SendsTo(converter)

	// TODO: allow overriding service name
	reporter := otel.NewReporter(
		processPath, config.TracesEndpoint, config.MetricsEndpoint)
	if err := reporter.Start(); err != nil {
		return Pipeline{}, fmt.Errorf("starting OTEL reporter: %w", err)
	}

	outNodes := 0
	if config.TracesEndpoint != "" {
		outNodes++
		converter.SendsTo(node.AsTerminal(reporter.ReportTraces))
	}

	if config.MetricsEndpoint != "" {
		outNodes++
		converter.SendsTo(node.AsTerminal(reporter.ReportMetrics))
	}

	if config.PrintTraces {
		outNodes++
		// Stdout output just for debugging
		converter.SendsTo(printerNode())
	}

	if outNodes == 0 {
		return Pipeline{}, fmt.Errorf("you should define at least one of OTEL_METRICS_ENDPOINT, OTEL_TRACES_ENDPOINT or PRINT_TRACES")
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
