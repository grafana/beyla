package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
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

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean-up if the
	// child process isn't found.
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-exit
		slog.Debug("Received termination signal", "signal", sig.String())
		erasePinnedMaps()
		cancel()
		os.Exit(1) // Must force exit, cancel will not work if we handn't found a process
	}()

	slog.Info("creating instrumentation pipeline")
	bp, err := pipe.Build(config)
	if err != nil {
		slog.Error("can't instantiate instrumentation pipeline", err)
		os.Exit(-1)
	}

	slog.Info("Starting main node")
	go bp.Run(ctx)

	<-ctx.Done()
	slog.Info("stopping auto-instrumenter")
}

func erasePinnedMaps() {
	if err := unix.Unmount(fs.PinnedRoot, unix.MNT_FORCE); err == nil {
		slog.Debug("unmounted bpf file system " + fs.PinnedRoot)
		if err := os.RemoveAll(fs.PinnedRoot); err != nil {
			slog.Error("can't remove pinned root "+fs.PinnedRoot, err)
		}
		slog.Debug("removed " + fs.PinnedRoot)
	} else {
		slog.Error("can't unmount pinned root "+fs.PinnedRoot, err)
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
