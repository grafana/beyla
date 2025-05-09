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

	_ "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"

	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/kubecache"
	"github.com/grafana/beyla/v2/pkg/kubecache/instrument"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
	"github.com/grafana/beyla/v2/pkg/kubecache/service"
)

// main code of te Kubernetes K8s informer's metadata cache service, when it runs as a separate service and not
// as a library inside Beyla

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	slog.Info("Beyla's Kubernetes Metadata cache service", "Version", buildinfo.Version, "Revision", buildinfo.Revision)

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()
	if cfg := os.Getenv("BEYLA_K8S_CACHE_CONFIG_PATH"); cfg != "" {
		configPath = &cfg
	}
	config := loadFromFile(configPath)
	if err := lvl.UnmarshalText([]byte(config.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", "error", err)
		}()
	}

	ic := service.InformersCache{Config: config}

	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// add the internal metrics to the context
	ctx = instrument.Start(ctx, &config.InternalMetrics)

	if err := ic.Run(ctx,
		meta.WithResyncPeriod(config.InformerResyncPeriod)); err != nil {
		slog.Error("starting informers' cache service", "error", err)
		os.Exit(-1)
	}
	slog.Info("service stopped. Exiting now")

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}

func loadFromFile(configPath *string) *kubecache.Config {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}
	config, err := kubecache.LoadConfig(configReader)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		// nolint:gocritic
		os.Exit(-1)
	}

	return config
}
