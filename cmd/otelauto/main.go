package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/fs"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe"

	_ "net/http/pprof"
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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		erasePinnedMaps()
		os.Exit(1)
	}()

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", err)
		}()
	}

	erasePinnedMaps()

	slog.Info("creating instrumentation pipeline")
	bp, err := pipe.Build(config)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")
	bp.Run(context.TODO())
}

func erasePinnedMaps() {
	for _, m := range fs.PinnedMaps {
		slog.Debug("cleaning storage used by pinned object", "map", m)
		err := os.Remove(filepath.Join(fs.PinnedRoot, m))
		if err != nil {
			slog.Error("can't remove pinned map "+m, err)
		}
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
