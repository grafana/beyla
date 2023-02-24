package main

import (
	"fmt"
	"os"

	"github.com/grafana/http-autoinstrument/pkg/instr"
	"github.com/grafana/http-autoinstrument/pkg/otel"

	"github.com/cilium/ebpf/link"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/context"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/http-autoinstrument/pkg/ebpf/process"

	"github.com/caarlos0/env/v6"
	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

type Config struct {
	Endpoint string `env:"OTEL_TRACES_ENDPOINT"`
	Exec     string `env:"EXECUTABLE_NAME"`
}

func main() {
	ho := slog.HandlerOptions{
		Level: slog.LevelDebug,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))

	config := Config{}
	if err := env.Parse(&config); err != nil {
		slog.Error("can't load configuration from environment", err)
		os.Exit(-1)
	}

	processPath, processElf, err := instr.FindProcess(config.Exec)
	panicOn(err)
	defer processElf.Close()

	pa := process.NewAnalyzer()
	// TODO: get rid of this
	target, err := pa.Analyze(processElf, map[string]interface{}{"net/http.HandlerFunc.ServeHTTP": struct{}{}})
	panicOn(err)

	// TODO: listen for new processes
	exe, err := link.OpenExecutable(processPath)
	panicOn(err)

	ctx := &context.InstrumentorContext{
		Executable:    exe,
		TargetDetails: target,
	}

	httpInstrumentor := nethttp.New()
	panicOn(httpInstrumentor.Load(ctx))

	traceNode := node.AsStart(httpInstrumentor.Run)
	trackerNode := node.AsMiddle(spanner.ConvertToSpan)
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
	slog.Info("Starting main node")
	traceNode.Start()
	wait := make(chan struct{})
	<-wait
}

func panicOn(err error) {
	if err != nil {
		panic(err)
	}
}
