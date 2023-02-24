package instrumenter

import (
	"fmt"

	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/exec"
	"github.com/grafana/http-autoinstrument/pkg/otel"
	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
)

func BuildPipeline(config Config) (*node.Start[nethttp.HttpRequestTrace], error) {
	processPath, processElf, err := exec.FindExecELF(config.Exec)
	if err != nil {
		return nil, fmt.Errorf("looking for executable ELF: %w", err)
	}
	defer processElf.Close()

	offsets, err := exec.GoInstrumentationPoints(processElf, config.FuncName)
	if err != nil {
		return nil, fmt.Errorf("searching for instrumentation points: %w", err)
	}

	instrumetedServe, err := nethttp.Instrument(processPath, offsets)
	if err != nil {
		return nil, fmt.Errorf("instrumenting executable: %w", err)
	}
	traceNode := node.AsStart(instrumetedServe.Run)
	trackerNode := node.AsMiddle(spanner.ConvertToSpan)
	// TODO: disable by default and allow enabling it from env var
	printerNode := node.AsTerminal(func(spans <-chan spanner.HttpRequestSpan) {
		for span := range spans {
			fmt.Printf("connection %s long: %#v\n", span.End.Sub(span.Start), span)
		}
	})
	report, err := otel.Report(config.Endpoint)
	if err != nil {
		panic(err)
	}
	otelNode := node.AsTerminal(report)
	traceNode.SendsTo(trackerNode)
	trackerNode.SendsTo(printerNode)
	trackerNode.SendsTo(otelNode)

	return traceNode, nil
}
