package main

import (
	"context"
	"encoding/json"
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

	otelsdk "go.opentelemetry.io/otel/sdk"
	"gopkg.in/yaml.v3"

	_ "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"

	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/buildinfo"
	"github.com/grafana/beyla/v3/pkg/components"
)

// configVersionV1 is the only configuration document version Beyla can load.
// OBI additionally understands "v2" (a `file_format` / `extensions.obi`
// document), but its loader lives in the module-internal packages
// go.opentelemetry.io/obi/internal/config/{schema,convert}, which Beyla cannot
// import — the local `replace` directive does not lift Go's internal-package
// rule, and OBI exposes no wrapper under pkg/. Supporting v2 here requires an
// exported versioned loader in OBI first.
const configVersionV1 = "v1"

func main() {
	lvl := slog.LevelVar{}
	lvl.Set(slog.LevelInfo)
	// Bootstrap logger. The configured handler can only be installed once the
	// configuration (and with it log_format) has been read, but loading it may
	// itself fail, so log through a default text handler until then.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &lvl,
	})))

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

	setupLogHandler(config.LogFormat, &lvl)

	slog.Info("Grafana Beyla", "Version", buildinfo.Version, "Revision", buildinfo.Revision, "OpenTelemetry SDK Version", otelsdk.Version())
	slog.Info("configuration loaded", "version", configVersionV1)

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

	logConfig(config)

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

// setupLogHandler installs the slog handler matching the configured
// log_format (BEYLA_LOG_FORMAT), replacing the bootstrap text handler.
// Mirrors .obi-src/cmd/obi/main.go.
func setupLogHandler(format obi.LogFormat, lvl *slog.LevelVar) {
	var handler slog.Handler
	switch obi.LogFormat(strings.ToLower(string(format))) {
	default:
		slog.Warn("unknown log format specified, defaulting to text", "format", format)
		fallthrough
	case obi.LogFormatText:
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	case obi.LogFormatJSON:
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	}
	slog.SetDefault(slog.New(handler))
}

func logConfig(config *beyla.Config) {
	if config.LogConfig == "" {
		return
	}
	var configString string
	configYaml, err := yaml.Marshal(config)
	if err != nil {
		slog.Warn("can't marshal configuration to YAML", "error", err)
		return
	}
	switch config.LogConfig {
	case obi.LogConfigOptionYAML:
		configString = string(configYaml)
	case obi.LogConfigOptionJSON:
		// instead of annotating the config with json tags, we unmarshal the YAML to a map[string]any, and marshal that map to
		var configMap map[string]any
		err = yaml.Unmarshal(configYaml, &configMap)
		if err != nil {
			slog.Warn("can't unmarshal yaml configuration to map", "error", err)
			break
		}
		configJSON, err := json.Marshal(configMap)
		if err != nil {
			slog.Warn("can't marshal configuration to JSON", "error", err)
			break
		}
		configString = string(configJSON)
	}
	if configString != "" {
		slog.Info("Running OpenTelemetry eBPF Instrumentation with configuration")
		fmt.Println(configString)
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
