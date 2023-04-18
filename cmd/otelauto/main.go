package main

import (
	"context"
	"flag"
	"io"
	"os"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/pipe"
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

	slog.Info("creating instrumentation pipeline")
	bp, err := pipe.Build(config)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")
	// TODO: add shutdown hook for graceful stop
	bp.Run(context.TODO())
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
