package main

import (
	"bytes"
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

	"go.opentelemetry.io/obi/cmd/obi/configbridge"
	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/obi"

	"github.com/grafana/beyla/v3/cmd/beyla/internal/configrefresh"
	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/buildinfo"
	"github.com/grafana/beyla/v3/pkg/components"
)

// config v2 is loaded through go.opentelemetry.io/obi/cmd/obi/configbridge,
// the module in scripts/obi-configbridge.
//
// The generated integration fixtures therefore carry OBI's v2 documents
// verbatim (modulo the OTEL_EBPF_* → BEYLA_* env renaming): appending
// v1-equivalent keys to them is no longer possible, since OBI's v2 document
// validator rejects unknown top-level fields.
const (
	configVersionV1 = "v1"
	configVersionV2 = "v2"
)

// nolint:cyclop
func main() {
	// `beyla config validate|migrate` is OBI's config command group. It reads OBI v1 files, so
	// it needs the same BEYLA_* to OTEL_EBPF_* environment mirroring as the regular config loader.
	if len(os.Args) > 1 && os.Args[1] == "config" {
		beyla.OverrideOBIGlobalConfig()
		if handled, code := configbridge.RunConfigCommand(os.Args[1:], os.Stdout, os.Stderr); handled {
			os.Exit(code)
		}
	}

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

	config, configVersion, configData := loadConfig(configPath)
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
	slog.Info("configuration loaded", "version", configVersion)

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
	var opts []components.Option
	if watchV2Config(configVersion, config, configPath) {
		go configbridge.Watch(ctx, *configPath, configData, config.RefreshCriteria)
	} else {
		opts = startConfigRefresh(ctx, config, *configPath, configData)
	}
	if err := components.RunBeyla(ctx, config, opts...); err != nil {
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

func loadConfig(configPath *string) (*beyla.Config, string, []byte) {
	// Mirror BEYLA_* onto OTEL_EBPF_* before either loader reads the environment.
	beyla.OverrideOBIGlobalConfig()

	var data []byte
	if configPath != nil && *configPath != "" {
		var err error
		data, err = os.ReadFile(*configPath)
		if err != nil {
			slog.Error("can't open "+*configPath, "error", err)
			os.Exit(-1)
		}
	}

	if obiCfg, err := configbridge.LoadV2(data); err == nil {
		cfg := beyla.FromOBI(obiCfg)
		selection := instrumentations.NewInstrumentationSelection(obiCfg.OTELMetrics.Instrumentations)
		var updater *discover.CriteriaUpdater
		if obiCfg.Enabled(obi.FeatureAppO11y) {
			updater = discover.NewCriteriaUpdater(obiCfg)
		}
		cfg.SetV2Runtime(selection, updater)
		return cfg, configVersionV2, data
	} else if !configbridge.IsNotV2(err) {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}

	var reader io.Reader
	if data != nil {
		reader = bytes.NewReader(data)
	}
	config, err := beyla.LoadConfig(reader)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}
	return config, configVersionV1, data
}

// watchV2Config reports whether config v2 should reload through OBI's watcher.
// The v1 refresher only understands the legacy document, so it must not replace
// these criteria.
func watchV2Config(version string, cfg *beyla.Config, configPath *string) bool {
	return version == configVersionV2 &&
		cfg.CriteriaUpdates() != nil &&
		configPath != nil && *configPath != ""
}

// startConfigRefresh lets the discovery criteria change without restarting Beyla: through the
// control socket of a parent process such as Alloy or, without one, by watching the
// configuration file. It returns the options that connect the refreshes to the pipeline.
func startConfigRefresh(ctx context.Context, config *beyla.Config, configPath string, configData []byte) []components.Option {
	conn, err := configrefresh.ControlConn()
	if err != nil {
		slog.Error("can't open the configuration control socket", "error", err)
	}

	if conn == nil && configPath == "" {
		return nil
	}

	refresher, err := configrefresh.New(config, configData)
	if err != nil {
		slog.Debug("discovery criteria refresh disabled", "reason", err)
		if conn != nil {
			go configrefresh.Serve(ctx, conn, func(context.Context, []byte) error { return err })
		}
		return nil
	}

	if conn != nil {
		go configrefresh.Serve(ctx, conn, refresher.Refresh)
	} else {
		go configrefresh.Watch(ctx, configPath, configData, refresher)
	}

	return []components.Option{components.WithCriteriaUpdater(refresher.Updater())}
}
