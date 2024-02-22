package beyla

import (
	"fmt"
	"io"
	"time"

	"github.com/caarlos0/env/v9"
	"gopkg.in/yaml.v3"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/export/debug"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/internal/transform"
)

const ReporterLRUSize = 256

// Features that can be enabled in Beyla (can be at the same time): App O11y and/or Net O11y
type Feature uint

const (
	FeatureAppO11y = Feature(1 << iota)
	FeatureNetO11y
)

var defaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	EBPF: ebpfcommon.TracerConfig{
		BatchLength:  100,
		BatchTimeout: time.Second,
		BpfBaseDir:   "/var/run/beyla",
	},
	Grafana: otel.GrafanaConfig{
		OTLP: otel.GrafanaOTLP{
			// by default we will only submit traces, assuming span2metrics will do the metrics conversion
			Submit: []string{"traces"},
		},
	},
	Metrics: otel.MetricsConfig{
		Protocol:             otel.ProtocolUnset,
		MetricsProtocol:      otel.ProtocolUnset,
		Interval:             5 * time.Second,
		Buckets:              otel.DefaultBuckets,
		ReportersCacheLen:    ReporterLRUSize,
		HistogramAggregation: otel.AggregationExplicit,
	},
	Traces: otel.TracesConfig{
		Protocol:           otel.ProtocolUnset,
		TracesProtocol:     otel.ProtocolUnset,
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
		ReportersCacheLen:  ReporterLRUSize,
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
	Attributes: Attributes{
		InstanceID: traces.InstanceIDConfig{
			HostnameDNSResolution: true,
		},
		Kubernetes: transform.KubernetesDecorator{
			Enable:               transform.EnabledDefault,
			InformersSyncTimeout: 30 * time.Second,
		},
	},
	Routes:       &transform.RoutesConfig{},
	NetworkFlows: defaultNetworkConfig,
}

type Config struct {
	EBPF ebpfcommon.TracerConfig `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows NetworkConfig `yaml:"network"`

	// Grafana overrides some values of the otel.MetricsConfig and otel.TracesConfig below
	// for a simpler submission of OTEL metrics to Grafana Cloud
	Grafana otel.GrafanaConfig `yaml:"grafana"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes     *transform.RoutesConfig `yaml:"routes"`
	Metrics    otel.MetricsConfig      `yaml:"otel_metrics_export"`
	Traces     otel.TracesConfig       `yaml:"otel_traces_export"`
	Prometheus prom.PrometheusConfig   `yaml:"prometheus_export"`
	Printer    debug.PrintEnabled      `yaml:"print_traces" env:"BEYLA_PRINT_TRACES"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	Exec services.RegexpAttr `yaml:"executable_name" env:"BEYLA_EXECUTABLE_NAME"`
	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port services.PortEnum `yaml:"open_port" env:"BEYLA_OPEN_PORT"`

	// ServiceName is taken from either BEYLA_SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility)
	// Using env and envDefault is a trick to get the value either from one of either variables
	ServiceName      string `yaml:"service_name" env:"OTEL_SERVICE_NAME,expand" envDefault:"${BEYLA_SERVICE_NAME}"`
	ServiceNamespace string `yaml:"service_namespace" env:"BEYLA_SERVICE_NAMESPACE"`

	// Discovery configuration
	Discovery services.DiscoveryConfig `yaml:"discovery"`

	LogLevel string `yaml:"log_level" env:"BEYLA_LOG_LEVEL"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen int               `yaml:"channel_buffer_len" env:"BEYLA_CHANNEL_BUFFER_LEN"`
	Noop             debug.NoopEnabled `yaml:"noop" env:"BEYLA_NOOP_TRACES"`
	ProfilePort      int               `yaml:"profile_port" env:"BEYLA_PROFILE_PORT"`
	InternalMetrics  imetrics.Config   `yaml:"internal_metrics"`
}

// Attributes configures the decoration of some extra attributes that will be
// added to each span
type Attributes struct {
	Kubernetes transform.KubernetesDecorator `yaml:"kubernetes"`
	InstanceID traces.InstanceIDConfig       `yaml:"instance_id"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

// nolint:cyclop
func (c *Config) Validate() error {
	if err := c.Discovery.Services.Validate(); err != nil {
		return ConfigError(fmt.Sprintf("error in services YAML property: %s", err.Error()))
	}
	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) {
		return ConfigError("missing at least one of BEYLA_NETWORK_METRICS, BEYLA_EXECUTABLE_NAME or BEYLA_OPEN_PORT property")
	}
	if (c.Port.Len() > 0 || c.Exec.IsSet() || len(c.Discovery.Services) > 0) && c.Discovery.SystemWide {
		return ConfigError("you can't use BEYLA_SYSTEM_WIDE if any of BEYLA_EXECUTABLE_NAME, BEYLA_OPEN_PORT or services (YAML) are set")
	}
	if c.EBPF.BatchLength == 0 {
		return ConfigError("BEYLA_BPF_BATCH_LENGTH must be at least 1")
	}

	if c.Enabled(FeatureNetO11y) && !c.Grafana.OTLP.MetricsEnabled() && !c.Metrics.Enabled() {
		return ConfigError("enabling network observability requires to enable at least the OpenTelemetry" +
			" metrics exporter: grafana or otel_metrics_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT or OTEL_EXPORTER_OTLP_METRICS_ENDPOINT environment variables")
	}

	if !c.Noop.Enabled() && !c.Printer.Enabled() &&
		!c.Grafana.OTLP.MetricsEnabled() && !c.Grafana.OTLP.TracesEnabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() &&
		!c.Prometheus.Enabled() {
		return ConfigError("you need to define at least one exporter: print_traces," +
			" grafana, otel_metrics_export, otel_traces_export or prometheus_export")
	}
	return nil
}

// Enabled checks if a given Beyla feature is enabled according to the global configuration
func (c *Config) Enabled(feature Feature) bool {
	switch feature {
	case FeatureNetO11y:
		return c.NetworkFlows.Enable
	case FeatureAppO11y:
		return c.Port.Len() > 0 || c.Exec.IsSet() || len(c.Discovery.Services) > 0 || c.Discovery.SystemWide
	}
	return false
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
