package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grafana/beyla/v3/pkg/ocihook"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	cfg, err := ocihook.ConfigFromEnv()
	if err != nil {
		slog.Error("invalid OCI wrapper configuration", "error", err)
		os.Exit(2)
	}
	configureLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	wrapper := ocihook.NewWrapper(cfg)
	if err := wrapper.Execute(ctx, os.Args[1:]); err != nil {
		slog.Error("OCI wrapper execution failed", "error", err)
		os.Exit(1)
	}
}

func configureLogger(level string) {
	lvl := slog.LevelVar{}
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl.Set(slog.LevelDebug)
	case "warn":
		lvl.Set(slog.LevelWarn)
	case "error":
		lvl.Set(slog.LevelError)
	default:
		lvl.Set(slog.LevelInfo)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &lvl,
	})))
}
