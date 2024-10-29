package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/grafana/beyla/pkg/kubecache/meta"
	"github.com/grafana/beyla/pkg/kubecache/service"
)

const defaultPort = 50055

// main code of te Kubernetes K8s informer's metadata cache service, when it runs as a separate service and not
// as a library inside Beyla

func main() {
	// TODO: use buildinfo to print version
	// TODO: let configure logger
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})))

	ic := service.InformersCache{
		Port: defaultPort,
	}
	portStr := os.Getenv("BEYLA_K8S_CACHE_PORT")
	if portStr != "" {
		var err error
		if ic.Port, err = strconv.Atoi(portStr); err != nil {
			slog.Error("invalid BEYLA_K8S_CACHE_PORT, using default port", "error", err)
			ic.Port = defaultPort
		}
	}

	// Adding shutdown hook for graceful stop.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	if err := ic.Run(ctx,
		// TODO: make it configurable
		meta.WithResyncPeriod(30*time.Minute)); err != nil {
		slog.Error("starting informers' cache service", "error", err)
		os.Exit(-1)
	}
	slog.Info("service stopped. Exiting now")

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}
