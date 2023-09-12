package pipe

import (
	"fmt"
	"io"
	"time"

	"github.com/caarlos0/env/v9"
	"gopkg.in/yaml.v3"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/export/debug"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/transform"
)

var defaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	EBPF: ebpfcommon.TracerConfig{
		BatchLength:  100,
		BatchTimeout: time.Second,
		BpfBaseDir:   "/var/run/beyla",
	},
	Metrics: otel.MetricsConfig{
		Protocol:          otel.ProtocolHTTPProtobuf,
		Interval:          5 * time.Second,
		Buckets:           otel.DefaultBuckets,
		ReportersCacheLen: 16,
	},
	Traces: otel.TracesConfig{
		Protocol:           otel.ProtocolHTTPProtobuf,
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
		SamplingRatio:      1.0,
		ReportersCacheLen:  16,
	},
	Prometheus: prom.PrometheusConfig{
		Path:    "/metrics",
		Buckets: otel.DefaultBuckets,
	},
	Printer: false,
	Noop:    false,
	InternalMetrics: imetrics.Config{
		Prometheus: imetrics.PrometheusConfig{
			Port: 0, // disabled by default
			Path: "/internal/metrics",
		},
	},
	Kubernetes: transform.KubernetesDecorator{
		Enable:               transform.EnabledDefault,
		InformersSyncTimeout: 30 * time.Second,
	},
}

type Config struct {
	EBPF ebpfcommon.TracerConfig `yaml:"ebpf"`

	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes     *transform.RoutesConfig       `yaml:"routes"`
	Kubernetes transform.KubernetesDecorator `yaml:"kubernetes"`
	Metrics    otel.MetricsConfig            `yaml:"otel_metrics_export"`
	Traces     otel.TracesConfig             `yaml:"otel_traces_export"`
	Prometheus prom.PrometheusConfig         `yaml:"prometheus_export"`
	Printer    debug.PrintEnabled            `yaml:"print_traces" env:"PRINT_TRACES"`

	LogLevel string `yaml:"log_level" env:"LOG_LEVEL"`

	// ServiceName is taken from either SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility)
	// Using env and envDefault is a trick to get the value either from one of either variables
	ServiceName      string `yaml:"service_name" env:"OTEL_SERVICE_NAME,expand" envDefault:"${SERVICE_NAME}"`
	ServiceNamespace string `yaml:"service_namespace" env:"SERVICE_NAMESPACE"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen int               `yaml:"channel_buffer_len" env:"CHANNEL_BUFFER_LEN"`
	Noop             debug.NoopEnabled `yaml:"noop" env:"NOOP_TRACES"`
	ProfilePort      int               `yaml:"profile_port" env:"PROFILE_PORT"`
	InternalMetrics  imetrics.Config   `yaml:"internal_metrics"`
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
		!c.Metrics.Enabled() && !c.Traces.Enabled() &&
		!c.Prometheus.Enabled() {
		return ConfigError("at least one of the following properties must be set: " +
			"NOOP_TRACES, PRINT_TRACES, OTEL_EXPORTER_OTLP_ENDPOINT, " +
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, BEYLA_PROMETHEUS_PORT")
	}
	return nil
}

// LoadConfig overrides configuration in the following order (from less to most priority)
// 1 - Default configuration (defaultConfig variable)
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
