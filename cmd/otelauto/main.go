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
	"golang.org/x/sys/unix"

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

	if config.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", config.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", err)
		}()
	}

	if err := mountBpfFS(); err != nil {
		slog.Error("error mounting bfs filesystem", err)
		os.Exit(1)
	}
	erasePinnedMaps()

	slog.Info("creating instrumentation pipeline")
	bp, err := pipe.Build(config)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")

	// Adding shutdown hook for graceful stop
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-exit
		slog.Debug("Received termination signal", "signal", sig.String())
		cancel()
	}()

	go bp.Run(ctx)

	<-ctx.Done()
	slog.Info("stopping auto-instrumenter")
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

func mountBpfFS() error {
	_, err := os.Stat(fs.PinnedRoot)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(fs.PinnedRoot, 0700); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	return unix.Mount(fs.PinnedRoot, fs.PinnedRoot, "bpf", 0, "")
}
