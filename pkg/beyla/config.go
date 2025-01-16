package beyla

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v9"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	"gopkg.in/yaml.v3"

	"github.com/grafana/beyla/pkg/config"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/debug"
	"github.com/grafana/beyla/pkg/export/instrumentations"
	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/export/prom"
	"github.com/grafana/beyla/pkg/internal/ebpf/tcmanager"
	"github.com/grafana/beyla/pkg/internal/filter"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/kubeflags"
	"github.com/grafana/beyla/pkg/services"
	"github.com/grafana/beyla/pkg/transform"
)

const ReporterLRUSize = 256

// Features that can be enabled in Beyla (can be at the same time): App O11y and/or Net O11y
type Feature uint

const (
	FeatureAppO11y = Feature(1 << iota)
	FeatureNetO11y
)

const (
	defaultMetricsTTL = 5 * time.Minute
)

var DefaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	EnforceSysCaps:   false,
	EBPF: config.EBPFTracer{
		BatchLength:        100,
		BatchTimeout:       time.Second,
		HTTPRequestTimeout: 30 * time.Second,
		TCBackend:          tcmanager.TCBackendAuto,
	},
	Grafana: otel.GrafanaConfig{
		OTLP: otel.GrafanaOTLP{
			// by default we will only submit traces, assuming span2metrics will do the metrics conversion
			Submit: []string{"traces"},
		},
	},
	NameResolver: &transform.NameResolverConfig{
		Sources:  []string{"k8s"},
		CacheLen: 1024,
		CacheTTL: 5 * time.Minute,
	},
	Metrics: otel.MetricsConfig{
		Protocol:        otel.ProtocolUnset,
		MetricsProtocol: otel.ProtocolUnset,
		// Matches Alloy and Grafana recommended scrape interval
		OTELIntervalMS:       60_000,
		Buckets:              otel.DefaultBuckets,
		ReportersCacheLen:    ReporterLRUSize,
		HistogramAggregation: otel.AggregationExplicit,
		Features:             []string{otel.FeatureApplication},
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
		// TODO: keep OTEL expiration disabled by default until we address
		// this issue: https://github.com/grafana/beyla/issues/1065
		TTL: defaultMetricsTTL,
	},
	Traces: otel.TracesConfig{
		Protocol:           otel.ProtocolUnset,
		TracesProtocol:     otel.ProtocolUnset,
		MaxQueueSize:       4096,
		MaxExportBatchSize: 4096,
		ReportersCacheLen:  ReporterLRUSize,
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
	},
	Prometheus: prom.PrometheusConfig{
		Path:     "/metrics",
		Buckets:  otel.DefaultBuckets,
		Features: []string{otel.FeatureApplication},
		Instrumentations: []string{
			instrumentations.InstrumentationALL,
		},
		TTL:                         defaultMetricsTTL,
		SpanMetricsServiceCacheSize: 10000,
	},
	Printer:      false, // Deprecated: use TracePrinter instead
	TracePrinter: debug.TracePrinterDisabled,
	InternalMetrics: imetrics.Config{
		Exporter: imetrics.InternalMetricsExporterDisabled,
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
			Enable:                kubeflags.EnabledDefault,
			InformersSyncTimeout:  30 * time.Second,
			InformersResyncPeriod: 30 * time.Minute,
			MetadataSources:       kube.DefaultMetadataSources,
		},
		HostID: HostIDConfig{
			FetchTimeout: 500 * time.Millisecond,
		},
	},
	Routes: &transform.RoutesConfig{
		Unmatch:      transform.UnmatchDefault,
		WildcardChar: "*",
	},
	NetworkFlows: defaultNetworkConfig,
	Processes: process.CollectConfig{
		RunMode:  process.RunModePrivileged,
		Interval: 5 * time.Second,
	},
	Discovery: services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
		ExcludeSystemServices:           `.*alloy.*|.*otelcol.*|.*beyla.*`,
	},
}

type Config struct {
	EBPF config.EBPFTracer `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows NetworkConfig `yaml:"network"`

	// Grafana overrides some values of the otel.MetricsConfig and otel.TracesConfig below
	// for a simpler submission of OTEL metrics to Grafana Cloud
	Grafana otel.GrafanaConfig `yaml:"grafana"`

	Filters filter.AttributesConfig `yaml:"filter"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes       *transform.RoutesConfig       `yaml:"routes"`
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`
	Metrics      otel.MetricsConfig            `yaml:"otel_metrics_export"`
	Traces       otel.TracesConfig             `yaml:"otel_traces_export"`
	Prometheus   prom.PrometheusConfig         `yaml:"prometheus_export"`
	Printer      debug.PrintEnabled            `yaml:"print_traces" env:"BEYLA_PRINT_TRACES"`
	TracePrinter debug.TracePrinter            `yaml:"trace_printer" env:"BEYLA_TRACE_PRINTER"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	Exec       services.RegexpAttr `yaml:"executable_name" env:"BEYLA_EXECUTABLE_NAME"`
	ExecOtelGo services.RegexpAttr `env:"OTEL_GO_AUTO_TARGET_EXE"`
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

	// Check for required system capabilities and bail if they are not
	// present. If set to 'false', Beyla will still print a list of missing
	// capabilities, but the execution will continue
	EnforceSysCaps bool `yaml:"enforce_sys_caps" env:"BEYLA_ENFORCE_SYS_CAPS"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen int             `yaml:"channel_buffer_len" env:"BEYLA_CHANNEL_BUFFER_LEN"`
	ProfilePort      int             `yaml:"profile_port" env:"BEYLA_PROFILE_PORT"`
	InternalMetrics  imetrics.Config `yaml:"internal_metrics"`

	// Processes metrics for application. They will be only enabled if there is a metrics exporter enabled,
	// and both the "application" and "application_process" features are enabled
	Processes process.CollectConfig `yaml:"processes"`

	// Grafana Agent specific configuration
	TracesReceiver TracesReceiverConfig `yaml:"-"`
}

type Consumer interface {
	otelconsumer.Traces
}

type TracesReceiverConfig struct {
	Traces []Consumer
}

func (t TracesReceiverConfig) Enabled() bool {
	return len(t.Traces) > 0
}

// Attributes configures the decoration of some extra attributes that will be
// added to each span
type Attributes struct {
	Kubernetes transform.KubernetesDecorator `yaml:"kubernetes"`
	InstanceID traces.InstanceIDConfig       `yaml:"instance_id"`
	Select     attributes.Selection          `yaml:"select"`
	HostID     HostIDConfig                  `yaml:"host_id"`
}

type HostIDConfig struct {
	// Override allows overriding the reported host.id in Beyla
	Override string `yaml:"override" env:"BEYLA_HOST_ID"`
	// HostIDFetchTimeout specifies the timeout for trying to fetch the HostID from diverse Cloud Providers
	FetchTimeout time.Duration `yaml:"fetch_timeout" env:"BEYLA_HOST_ID_FETCH_TIMEOUT"`
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
	if err := c.Discovery.ExcludeServices.Validate(); err != nil {
		return ConfigError(fmt.Sprintf("error in exclude_services YAML property: %s", err.Error()))
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
	if !c.EBPF.TCBackend.Valid() {
		return ConfigError("Invalid BEYLA_BPF_TC_BACKEND value")
	}

	if c.Attributes.Kubernetes.InformersSyncTimeout == 0 {
		return ConfigError("BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT duration must be greater than 0s")
	}

	if c.Enabled(FeatureNetO11y) && !c.Grafana.OTLP.MetricsEnabled() && !c.Metrics.Enabled() &&
		!c.Prometheus.Enabled() && !c.NetworkFlows.Print {
		return ConfigError("enabling network metrics requires to enable at least the OpenTelemetry" +
			" metrics exporter: grafana, otel_metrics_export or prometheus_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or BEYLA_PROMETHEUS_PORT environment variables. For debugging" +
			" purposes, you can also set BEYLA_NETWORK_PRINT_FLOWS=true")
	}

	if !c.TracePrinter.Valid() {
		return ConfigError(fmt.Sprintf("invalid value for trace_printer: '%s'", c.TracePrinter))
	}

	if c.Printer.Enabled() && c.TracePrinter.Enabled() {
		return ConfigError("print_traces and trace_printer are mutually exclusive, use trace_printer instead")
	}

	// TODO Printer is deprecated, remove
	if c.Printer.Enabled() {
		slog.Warn("'print_traces' configuration option has been deprecated and will be removed" +
			" in the future - use 'trace_printer' instead")
		c.TracePrinter = debug.TracePrinterText
	}

	if c.Enabled(FeatureAppO11y) && !c.Printer.Enabled() &&
		!c.Grafana.OTLP.MetricsEnabled() && !c.Grafana.OTLP.TracesEnabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() &&
		!c.Prometheus.Enabled() && !c.TracePrinter.Enabled() {
		return ConfigError("you need to define at least one exporter: trace_printer," +
			" grafana, otel_metrics_export, otel_traces_export or prometheus_export")
	}

	if len(c.Routes.WildcardChar) > 1 {
		return ConfigError("wildcard_char can only be a single character, multiple characters are not allowed")
	}

	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && c.InternalMetrics.Prometheus.Port != 0 {
		return ConfigError("you can't enable both OTEL and Prometheus internal metrics")
	}
	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && !c.Metrics.Enabled() && !c.Grafana.OTLP.MetricsEnabled() {
		return ConfigError("you can't enable OTEL internal metrics without enabling OTEL metrics")
	}

	return nil
}

func (c *Config) promNetO11yEnabled() bool {
	return c.Prometheus.Enabled() && c.Prometheus.NetworkMetricsEnabled()
}

func (c *Config) otelNetO11yEnabled() bool {
	return (c.Metrics.Enabled() || c.Grafana.OTLP.MetricsEnabled()) && c.Metrics.NetworkMetricsEnabled()
}

// Enabled checks if a given Beyla feature is enabled according to the global configuration
func (c *Config) Enabled(feature Feature) bool {
	switch feature {
	case FeatureNetO11y:
		return c.NetworkFlows.Enable || c.promNetO11yEnabled() || c.otelNetO11yEnabled()
	case FeatureAppO11y:
		return c.Port.Len() > 0 || c.Exec.IsSet() || len(c.Discovery.Services) > 0 || c.Discovery.SystemWide
	}
	return false
}

// ExternalLogger sets the logging capabilities of Beyla.
// Used for integrating Beyla with an external logging system (for example Alloy)
// TODO: maybe this method has too many responsibilities, as it affects the global logger.
func (c *Config) ExternalLogger(handler slog.Handler, tracing bool) {
	slog.SetDefault(slog.New(handler))
	if tracing {
		c.TracePrinter = debug.TracePrinterText
		c.EBPF.BpfDebug = true
		if c.NetworkFlows.Enable {
			c.NetworkFlows.Print = true
		}
	}
}

// LoadConfig overrides configuration in the following order (from less to most priority)
// 1 - Default configuration (defaultConfig variable)
// 2 - Contents of the provided file reader (nillable)
// 3 - Environment variables
func LoadConfig(file io.Reader) (*Config, error) {
	cfg := DefaultConfig
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

	// We support OTEL_GO_AUTO_TARGET_EXE as an alias to BEYLA_EXECUTABLE_NAME
	if !cfg.Exec.IsSet() && cfg.ExecOtelGo.IsSet() {
		cfg.Exec = cfg.ExecOtelGo
	}

	return &cfg, nil
}
