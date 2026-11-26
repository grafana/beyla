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
	"path/filepath"
	"slices"
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

	var flagPaths configPaths
	flag.Var(&flagPaths, "config", "path to a configuration file. Repeat the flag to layer several files, in increasing order of priority")
	flag.Parse()

	paths := configFilePaths(flagPaths, os.Getenv("BEYLA_CONFIG_PATH"))
	config, configVersion, configSources := loadConfig(paths)
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
	if watchV2Config(configVersion, config, configSources) {
		go configbridge.WatchSources(ctx, configSources, config.RefreshCriteria)
	} else {
		opts = startConfigRefresh(ctx, config, configSources)
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

// configPaths is a repeatable string flag.
type configPaths []string

func (p *configPaths) String() string {
	return strings.Join(*p, ",")
}

func (p *configPaths) Set(path string) error {
	*p = append(*p, path)
	return nil
}

// configFilePaths returns the configuration files in increasing order of priority:
// the -config flags in order, then the files in BEYLA_CONFIG_PATH, separated by the
// OS path list separator (colon on Linux), from left to right.
func configFilePaths(flags []string, envPaths string) []string {
	paths := slices.Clone(flags)
	for _, path := range filepath.SplitList(envPaths) {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func loadConfig(paths []string) (*beyla.Config, string, []configbridge.Source) {
	// Mirror BEYLA_* onto OTEL_EBPF_* before either loader reads the environment.
	beyla.OverrideOBIGlobalConfig()

	sources := make([]configbridge.Source, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("can't open "+path, "error", err)
			os.Exit(-1)
		}
		sources = append(sources, configbridge.Source{Path: path, Data: data})
	}

	cfg, version, err := loadConfigSources(sources)
	if err != nil {
		slog.Error("wrong configuration", "error", err)
		os.Exit(-1)
	}
	return cfg, version, sources
}

func loadConfigSources(sources []configbridge.Source) (*beyla.Config, string, error) {
	merged, err := configbridge.MergeSources(sources)
	if err != nil {
		return nil, "", err
	}

	if merged.Version == configbridge.VersionV2 {
		obiCfg, err := configbridge.LoadV2(merged.Data)
		if err != nil {
			return nil, "", err
		}
		cfg := beyla.FromOBI(obiCfg)
		selection := instrumentations.NewInstrumentationSelection(obiCfg.OTELMetrics.Instrumentations)
		var updater *discover.CriteriaUpdater
		if obiCfg.Enabled(obi.FeatureAppO11y) {
			updater = discover.NewCriteriaUpdater(obiCfg)
		}
		cfg.SetV2Runtime(selection, updater)
		return cfg, configVersionV2, nil
	}

	var reader io.Reader
	if len(sources) > 0 {
		reader = bytes.NewReader(merged.Data)
	}
	cfg, err := beyla.LoadConfigWithOverrides(reader, applyV2Shared(merged.Shared))
	if err != nil {
		return nil, "", err
	}
	return cfg, configVersionV1, nil
}

// applyV2Shared applies the settings that v2 files can override in a v1 base.
func applyV2Shared(shared *configbridge.V1Shared) func(*beyla.Config) {
	if shared == nil {
		return nil
	}
	return func(cfg *beyla.Config) {
		if shared.LogLevel != nil {
			cfg.LogLevel = *shared.LogLevel
		}
		if shared.LogFormat != nil {
			cfg.LogFormat = obi.LogFormat(*shared.LogFormat)
		}
		if shared.ShutdownTimeout != nil {
			cfg.ShutdownTimeout = *shared.ShutdownTimeout
		}
		if shared.ChannelBufferLen != nil {
			cfg.ChannelBufferLen = *shared.ChannelBufferLen
		}
		if shared.ChannelSendTimeout != nil {
			cfg.ChannelSendTimeout = *shared.ChannelSendTimeout
		}
		if shared.ChannelSendTimeoutPanic != nil {
			cfg.ChannelSendTimeoutPanic = *shared.ChannelSendTimeoutPanic
		}
	}
}

// watchV2Config reports whether config v2 should reload through the bridge watcher.
// The v1 refresher only understands the legacy document, so it must not replace
// these criteria.
func watchV2Config(version string, cfg *beyla.Config, sources []configbridge.Source) bool {
	return version == configVersionV2 &&
		cfg.CriteriaUpdates() != nil &&
		len(sources) > 0
}

// startConfigRefresh lets discovery and trace sampling change without restarting Beyla through the
// control socket of a parent process such as Alloy or, without one, by watching the
// configuration file. It returns the options that connect the refreshes to the pipeline.
func startConfigRefresh(ctx context.Context, config *beyla.Config, sources []configbridge.Source) []components.Option {
	conn, err := configrefresh.ControlConn()
	if err != nil {
		slog.Error("can't open the configuration control socket", "error", err)
	}

	// The v1 file watcher reads a single file. With layered files, only the control socket
	// can refresh the criteria.
	var configPath string
	var configData []byte
	if len(sources) == 1 {
		configPath, configData = sources[0].Path, sources[0].Data
	} else if len(sources) > 1 {
		slog.Debug("discovery criteria refresh from files is not available with multiple v1 configuration files")
		merged, err := configbridge.MergeSources(sources)
		if err != nil {
			slog.Error("can't merge the configuration files", "error", err)
			return nil
		}
		configData = merged.Data
	}

	if conn == nil && configPath == "" {
		return nil
	}

	refresher, err := configrefresh.New(config, configData)
	if err != nil {
		slog.Debug("configuration refresh disabled", "reason", err)
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

	if updater := refresher.Updater(); updater != nil {
		return []components.Option{components.WithCriteriaUpdater(updater)}
	}
	return nil
}
