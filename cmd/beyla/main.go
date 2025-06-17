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
	"strings"
	"syscall"
	"time"

	obi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
	otelsdk "go.opentelemetry.io/otel/sdk"

	_ "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/components"
)

func main() {
	setupOBIEnvVars()
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

	slog.Info("Grafana Beyla", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())

	if err := obi.CheckOSSupport(); err != nil {
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

	if err := obi.CheckOSCapabilities(config.AsOBI()); err != nil {
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

func appendAlternateEnvVar(env, oldPrefix, altPrefix string) bool {
	oldLen := len(oldPrefix)
	if len(env) > (oldLen+1) && strings.HasPrefix(env, oldPrefix) {
		eqIdx := strings.IndexByte(env, '=')
		if eqIdx > (oldLen + 1) {
			key := env[:eqIdx]
			val := env[eqIdx+1:]
			newKey := altPrefix + key[oldLen:]
			// Only set if not already set
			if os.Getenv(newKey) == "" {
				os.Setenv(newKey, val)
			}
			return true
		}
	}
	return false
}

// Duplicates any BEYLA_ prefixed environment variables with the OTEL_EBPF_ prefix
// and vice versa
func setupOBIEnvVars() {
	for _, env := range os.Environ() {
		appended := appendAlternateEnvVar(env, "BEYLA_", "OTEL_EBPF_")
		if !appended {
			appendAlternateEnvVar(env, "OTEL_EBPF_", "BEYLA_")
		}
	}
}
