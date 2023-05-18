package pipe

import (
	"fmt"
	"io"
	"time"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"

	"github.com/caarlos0/env/v7"
	"gopkg.in/yaml.v3"

	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/prom"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

var defaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	EBPF: ebpfcommon.TracerConfig{
		BatchLength:  100,
		BatchTimeout: time.Second,
		BpfBaseDir:   "/var/run/otelauto",
	},
	Metrics: otel.MetricsConfig{
		Interval: 5 * time.Second,
	},
	Traces: otel.TracesConfig{
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
	},
	Prometheus: prom.PrometheusConfig{
		Path: "/metrics",
	},
	Printer: false,
	Noop:    false,
}

type Config struct {
	EBPF ebpfcommon.TracerConfig `nodeId:"ebpf" sendTo:"routes" yaml:"ebpf"`

	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes *transform.RoutesConfig `nodeId:"routes" forwardTo:"otel_metrics,otel_traces,print,noop,prom" yaml:"routes"`

	Metrics    otel.MetricsConfig    `nodeId:"otel_metrics" yaml:"otel_metrics_export"`
	Traces     otel.TracesConfig     `nodeId:"otel_traces" yaml:"otel_traces_export"`
	Prometheus prom.PrometheusConfig `nodeId:"prom" yaml:"prometheus_export"`
	Printer    debug.PrintEnabled    `nodeId:"print" yaml:"print_traces" env:"PRINT_TRACES"`

	LogLevel string `yaml:"log_level" env:"LOG_LEVEL" nodeId:"-"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen int               `yaml:"channel_buffer_len" env:"CHANNEL_BUFFER_LEN" nodeId:"-"`
	Noop             debug.NoopEnabled `nodeId:"noop" yaml:"noop" env:"NOOP_TRACES"`
	ProfilePort      int               `yaml:"profile_port" env:"PROFILE_PORT" nodeId:"-"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

func (c *Config) validateInstrumentation() error {
	if c.EBPF.Port == 0 && c.EBPF.Exec == "" && !c.EBPF.SystemWide {
		return ConfigError("missing EXECUTABLE_NAME, OPEN_PORT or SYSTEM_WIDE property")
	}
	if (c.EBPF.Port != 0 || c.EBPF.Exec != "") && c.EBPF.SystemWide {
		return ConfigError("use either SYSTEM_WIDE or any of EXECUTABLE_NAME and OPEN_PORT, not both")
	}
	if c.EBPF.BatchLength == 0 {
		return ConfigError("BATCH_LENGTH must be at least 1")
	}
	return nil
}

func (c *Config) Validate() error {
	if err := c.validateInstrumentation(); err != nil {
		return err
	}

	if !c.Noop.Enabled() && !c.Printer.Enabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() {
		return ConfigError("at least one of the following properties must be set: " +
			"NOOP_TRACES, PRINT_TRACES, OTEL_EXPORTER_OTLP_ENDPOINT, " +
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	return nil
}

// LoadConfig overrides configuration in the following order (from less to most priority)
// 1 - Default configuration (default_config.yml)
// 2 - Contents of the provided file reader (nillable)
// 3 - Environment variables
func LoadConfig(file io.Reader) (*Config, error) {
	cfg := defaultConfig
	if file != nil {
		cfgBuf, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("reading YAML configuration: %w", err)
		}
		if err := yaml.Unmarshal(cfgBuf, &cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML configuration: %w", err)
		}
	}
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("reading env vars: %w", err)
	}
	return &cfg, nil
}
