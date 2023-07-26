package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/connector"
	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf"
	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
)

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	ho := slog.HandlerOptions{
		Level: &lvl,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stdout)))

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	config := loadConfig(configPath)

	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", err)
		os.Exit(-1)
	}

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", err)
		}()
	}

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	ctxInfo := BuildContextInfo(config)

	slog.Info("creating instrumentation pipeline")
	tracer, err := ebpf.FindAndInstrument(ctx, &config.EBPF, ctxInfo.Metrics)
	if err != nil {
		slog.Error("can't find an instrument executable", err)
		os.Exit(-1)
	}
	if ctxInfo.ServiceName == "" {
		ctxInfo.ServiceName = tracer.ELFInfo.ExecutableName()
	}

	bp, err := pipe.Build(ctx, config, ctxInfo, tracer)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")

	bp.Run(ctx)

	slog.Info("exiting auto-instrumenter")

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}

func loadConfig(configPath *string) *pipe.Config {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}
	config, err := pipe.LoadConfig(configReader)
	if err != nil {
		slog.Error("wrong configuration", err)
		os.Exit(-1)
	}
	return config
}

func BuildContextInfo(config *pipe.Config) *global.ContextInfo {
	promMgr := &connector.PrometheusManager{}
	ctxInfo := &global.ContextInfo{
		ReportRoutes:     config.Routes != nil,
		Prometheus:       promMgr,
		ServiceName:      config.ServiceName,
		ServiceNamespace: config.ServiceNamespace,
	}
	if config.InternalMetrics.Prometheus.Port != 0 {
		slog.Debug("reporting internal metrics as Prometheus")
		ctxInfo.Metrics = imetrics.NewPrometheusReporter(&config.InternalMetrics.Prometheus, promMgr)
		// Prometheus manager also has its own internal metrics, so we need to pass the imetrics reporter
		// TODO: remove this dependency cycle and let prommgr to create and return the PrometheusReporter
		promMgr.InstrumentWith(ctxInfo.Metrics)
	} else {
		slog.Debug("not reporting internal metrics")
		ctxInfo.Metrics = imetrics.NoopReporter{}
	}
	return ctxInfo
}
