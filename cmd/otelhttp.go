package main

import (
	"errors"
	"os"

	"github.com/grafana/http-autoinstrument/pkg/pipe"

	"github.com/caarlos0/env/v6"
	"golang.org/x/exp/slog"
)

func main() {
	lvl := slog.LevelDebug

	lvlEnv, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL is set, let's default to the desired level
	if ok {
		err := lvl.UnmarshalText([]byte(lvlEnv))
		if err != nil {
			slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", errors.New(lvlEnv))
			os.Exit(-1)
		}
	}

	ho := slog.HandlerOptions{
		Level: lvl,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))

	config := pipe.Config{}
	if err := env.Parse(&config); err != nil {
		slog.Error("can't load configuration from environment", err)
		os.Exit(-1)
	}

	slog.Info("creating instrumentation pipeline")
	bp, err := pipe.Build(&config)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")
	bp.Start()

	// TODO: add shutdown hook for graceful stop
	wait := make(chan struct{})
	<-wait
}
