package main

import (
	"fmt"
	"github.com/grafana/http-autoinstrument/pkg/otel"
	tracer "github.com/mariomac/ebpf-template/pkg/ebpf"
	"os"

	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

const (
	envEndpoint = "OTEL_TRACES_ENDPOINT"
)

func main() {
	tracesEndpoint, ok := os.LookupEnv(envEndpoint)
	if !ok {
		fmt.Fprintf(os.Stderr, "missing "+envEndpoint)
		os.Exit(-1)
	}
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))
	traceFunc, err := tracer.Trace()
	if err != nil {
		panic(err)
	}
	traceNode := node.AsStart(traceFunc)
	trackerNode := node.AsMiddle(spanner.ConvertToSpan)
	printerNode := node.AsTerminal(func(spans <-chan spanner.ConnectionSpan) {
		for span := range spans {
			fmt.Printf("connection %s long: %#v\n", span.End.Sub(span.Start), span)
		}
	})
	report, err := otel.Report(tracesEndpoint)
	if err != nil {
		panic(err)
	}
	otelNode := node.AsTerminal(report)
	traceNode.SendsTo(trackerNode)
	trackerNode.SendsTo(printerNode)
	trackerNode.SendsTo(otelNode)
	slog.Info("Starting main node")
	traceNode.Start()
	wait := make(chan struct{})
	<-wait
}
