package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	otelsdk "go.opentelemetry.io/otel/sdk"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/buildinfo"
	"github.com/grafana/beyla/pkg/components"
)

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	slog.Info("Grafana Beyla", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())

	if err := beyla.CheckOSSupport(); err != nil {
		slog.Error("can't start Beyla", "error", err)
		os.Exit(-1)
	}

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	if cfg := os.Getenv("BEYLA_CONFIG_PATH"); cfg != "" {
		configPath = &cfg
	}

	config := loadConfig(configPath)
	if err := config.Validate(); err != nil {
		slog.Error("wrong Beyla configuration", "error", err)
		os.Exit(-1)
	}

	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}

	if err := beyla.CheckOSCapabilities(config); err != nil {
		if config.EnforceSysCaps {
			slog.Error("can't start Beyla", "error", err)
			os.Exit(-1)
		}

		slog.Warn("Required system capabilities not present, Beyla may malfunction", "error", err)
	}

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", "error", err)
		}()
	}

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	if err := components.RunBeyla(ctx, config); err != nil {
		slog.Error("Beyla ran with errors", "error", err)
		os.Exit(-1)
	}

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}

func loadConfig(configPath *string) *beyla.Config {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}
	config, err := beyla.LoadConfig(configReader)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		// nolint:gocritic
		os.Exit(-1)
	}
	return config
}
