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
	"github.com/grafana/beyla/pkg/beyla/config"
	"github.com/grafana/beyla/pkg/beyla/flows/agent"
)

var Version = "main"

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	slog.Info("Grafana Beyla", "Version", Version, "OpenTelemetry SDK Version", otelsdk.Version())

	configPath := flag.String("config", "", "path to the configuration file")
	flag.Parse()

	globalConfig := loadConfig(configPath)

	beylaFeatures, err := globalConfig.Validate()
	if err != nil {
		slog.Error("wrong Beyla configuration", "error", err)
		os.Exit(-1)
	}

	if err := lvl.UnmarshalText([]byte(globalConfig.LogLevel)); err != nil {
		slog.Error("unknown log level specified, choices are [DEBUG, INFO, WARN, ERROR]", err)
		os.Exit(-1)
	}

	if globalConfig.ProfilePort != 0 {
		go func() {
			slog.Info("starting PProf HTTP listener", "port", globalConfig.ProfilePort)
			err := http.ListenAndServe(fmt.Sprintf(":%d", globalConfig.ProfilePort), nil)
			slog.Error("PProf HTTP listener stopped working", err)
		}()
	}

	// Adding shutdown hook for graceful stop.
	// We must register the hook before we launch the pipe build, otherwise we won't clean up if the
	// child process isn't found.
	ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	// TODO: move this logic into "beyla" package
	if beylaFeatures.Has(config.FeatureAppO11y) {
		setupAppO11y(ctx, globalConfig)
	}
	if beylaFeatures.Has(config.FeatureNetO11y) {
		setupNetO11y(ctx, globalConfig)
	}

	if gc := os.Getenv("GOCOVERDIR"); gc != "" {
		slog.Info("Waiting 1s to collect coverage data...")
		time.Sleep(time.Second)
	}
}

func setupAppO11y(ctx context.Context, config *config.Config) {
	slog.Info("starting Beyla in Application Observability mode")
	// TODO: when we split Beyla in two executables, this code can be split:
	// in two parts:
	// 1st executable - Invoke FindTarget, which also mounts the BPF maps
	// 2nd executable - Invoke ReadAndForward, receiving the BPF map mountpoint as argument
	instr := beyla.New(config)
	if err := instr.FindAndInstrument(ctx); err != nil {
		slog.Error("Beyla couldn't find target process", "error", err)
		os.Exit(-1)
	}
	if err := instr.ReadAndForward(ctx); err != nil {
		slog.Error("Beyla couldn't start read and forwarding", "error", err)
		os.Exit(-1)
	}
}

func setupNetO11y(ctx context.Context, cfg *config.Config) {
	slog.Info("starting Beyla in Network Observability mode")
	netCfg := cfg.Network
	// TODO: specify default somewhere else
	if netCfg.DeduperFCExpiry == 0 {
		netCfg.DeduperFCExpiry = 2 * netCfg.CacheActiveTimeout
	}
	flowsAgent, err := agent.FlowsAgent(&netCfg)
	if err != nil {
		slog.Error("can't start network observability", "error", err)
		os.Exit(-1)
	}
	if err := flowsAgent.Run(ctx); err != nil {
		slog.Error("can't start network observability", "error", err)
		os.Exit(-1)
	}
}

func loadConfig(configPath *string) *config.Config {
	var configReader io.ReadCloser
	if configPath != nil && *configPath != "" {
		var err error
		if configReader, err = os.Open(*configPath); err != nil {
			slog.Error("can't open "+*configPath, err)
			os.Exit(-1)
		}
		defer configReader.Close()
	}
	cfg, err := config.LoadConfig(configReader)
	if err != nil {
		slog.Error("wrong configuration", err)
		os.Exit(-1)
	}
	return cfg
}
