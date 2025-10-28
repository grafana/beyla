package beyla

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/caarlos0/env/v9"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v2/pkg/config"
	botel "github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/otel/spanscfg"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
	servicesextra "github.com/grafana/beyla/v2/pkg/services"
)

const ReporterLRUSize = 256

// Features that can be enabled in Beyla (can be at the same time): App O11y and/or Net O11y
type Feature uint

const (
	FeatureAppO11y = Feature(1 << iota)
	FeatureNetO11y
)

// DefaultConfig loads OBI's default configuration, and converts it to Beyla's Config type,
// overriding here any value that differs from the OBI defaults
func DefaultConfig() *Config {
	def := FromOBI(&obi.DefaultConfig)
	def.Grafana = botel.GrafanaConfig{
		OTLP: botel.GrafanaOTLP{
			// by default we will only submit traces, assuming span2metrics will do the metrics conversion
			Submit: []string{"traces"},
		},
	}
	def.Processes = process.CollectConfig{
		RunMode:  process.RunModePrivileged,
		Interval: 5 * time.Second,
	}
	def.Discovery.DefaultExcludeServices = servicesextra.DefaultExcludeServices
	def.Discovery.DefaultExcludeInstrument = servicesextra.DefaultExcludeInstrument
	return def
}

type Config struct {
	EBPF obicfg.EBPFTracer `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows obi.NetworkConfig `yaml:"network"`

	// Grafana overrides some values of the otel.MetricsConfig and otel.TracesConfig below
	// for a simpler submission of OTEL metrics to Grafana Cloud
	Grafana botel.GrafanaConfig `yaml:"grafana"`

	Filters filter.AttributesConfig `yaml:"filter"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes *transform.RoutesConfig `yaml:"routes"`
	// nolint:undoc
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`
	Metrics      otelcfg.MetricsConfig         `yaml:"otel_metrics_export"`
	Traces       otelcfg.TracesConfig          `yaml:"otel_traces_export"`
	Prometheus   prom.PrometheusConfig         `yaml:"prometheus_export"`
	TracePrinter debug.TracePrinter            `yaml:"trace_printer" env:"BEYLA_TRACE_PRINTER"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	// Deprecated: Use BEYLA_AUTO_TARGET_EXE
	//nolint:undoc
	Exec services.RegexpAttr `yaml:"executable_name" env:"BEYLA_EXECUTABLE_NAME"`

	// AutoTargetExe selects the executable to instrument matching a Glob against the executable path.
	// To set this value via YAML, use discovery > instrument.
	// It also accepts BEYLA_AUTO_TARGET_EXE for compatibility with opentelemetry-go-instrumentation
	AutoTargetExe services.GlobAttr `env:"BEYLA_AUTO_TARGET_EXE,expand" envDefault:"${OTEL_GO_AUTO_TARGET_EXE}"`

	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port services.PortEnum `yaml:"open_port" env:"BEYLA_OPEN_PORT"`

	// ServiceName is taken from either BEYLA_SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility)
	// Using env and envDefault is a trick to get the value either from one of either variables.
	// Deprecated: Service name should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	//nolint:undoc
	ServiceName string `yaml:"service_name" env:"OTEL_SERVICE_NAME,expand" envDefault:"${BEYLA_SERVICE_NAME}"`
	// Deprecated: Service namespace should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	//nolint:undoc
	ServiceNamespace string `yaml:"service_namespace" env:"BEYLA_SERVICE_NAMESPACE"`

	// Discovery configuration
	Discovery servicesextra.BeylaDiscoveryConfig `yaml:"discovery"`

	LogLevel string `yaml:"log_level" env:"BEYLA_LOG_LEVEL"`

	// Timeout for a graceful shutdown
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"BEYLA_SHUTDOWN_TIMEOUT"`

	// Check for required system capabilities and bail if they are not
	// present. If set to 'false', Beyla will still print a list of missing
	// capabilities, but the execution will continue
	EnforceSysCaps bool `yaml:"enforce_sys_caps" env:"BEYLA_ENFORCE_SYS_CAPS"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	// nolint:undoc
	ChannelBufferLen int `yaml:"channel_buffer_len" env:"BEYLA_CHANNEL_BUFFER_LEN"`
	// nolint:undoc
	ProfilePort     int             `yaml:"profile_port" env:"BEYLA_PROFILE_PORT"`
	InternalMetrics imetrics.Config `yaml:"internal_metrics"`

	// Processes metrics for application. They will be only enabled if there is a metrics exporter enabled,
	// and both the "application" and "application_process" features are enabled
	Processes process.CollectConfig `yaml:"processes"`

	// Grafana Alloy specific configuration
	TracesReceiver TracesReceiverConfig `yaml:"-"`

	// LogConfig enables the logging of the configuration on startup.
	// nolint:undoc
	LogConfig obi.LogConfigOption `yaml:"log_config" env:"BEYLA_LOG_CONFIG"`

	// nolint:undoc
	NodeJS obi.NodeJSConfig `yaml:"nodejs"`

	// Topology enables extra topology-related features, such as inter-cluster connection spans.
	// nolint:undoc
	Topology spanscfg.Topology `yaml:"topology"`

	// cached equivalent for the OBI conversion
	obi *obi.Config `yaml:"-"`
}

type Consumer interface {
	otelconsumer.Traces
}

type TracesReceiverConfig struct {
	Traces           []Consumer
	Sampler          services.SamplerConfig `yaml:"sampler"`
	Instrumentations []string               `yaml:"instrumentations" env:"BEYLA_OTEL_TRACES_INSTRUMENTATIONS" envSeparator:","`
}

func (t TracesReceiverConfig) Enabled() bool {
	return len(t.Traces) > 0
}

// Attributes configures the decoration of some extra attributes that will be
// added to each span
type Attributes struct {
	Kubernetes           transform.KubernetesDecorator `yaml:"kubernetes"`
	InstanceID           obicfg.InstanceIDConfig       `yaml:"instance_id"`
	Select               attributes.Selection          `yaml:"select"`
	HostID               HostIDConfig                  `yaml:"host_id"`
	ExtraGroupAttributes map[string][]attr.Name        `yaml:"extra_group_attributes"`

	// RenameUnresolvedHosts will replace HostName and PeerName attributes when they are empty or contain
	// unresolved IP addresses to reduce cardinality.
	// Set this value to the empty string to disable this feature.
	// nolint:undoc
	RenameUnresolvedHosts string `yaml:"rename_unresolved_hosts" env:"BEYLA_RENAME_UNRESOLVED_HOSTS"`
	// nolint:undoc
	RenameUnresolvedHostsOutgoing string `yaml:"rename_unresolved_hosts_outgoing" env:"BEYLA_RENAME_UNRESOLVED_HOSTS_OUTGOING"`
	// nolint:undoc
	RenameUnresolvedHostsIncoming string `yaml:"rename_unresolved_hosts_incoming" env:"BEYLA_RENAME_UNRESOLVED_HOSTS_INCOMING"`

	// MetricSpanNameAggregationLimit works PER SERVICE and only relates to span_metrics.
	// When the span_name cardinality surpasses this limit, the span_name will be reported as AGGREGATED.
	// If the value <= 0, it is disabled.
	// nolint:undoc
	MetricSpanNameAggregationLimit int `yaml:"metric_span_names_limit" env:"BEYLA_METRIC_SPAN_NAMES_LIMIT"`
}

type HostIDConfig struct {
	// Override allows overriding the reported host.id in Beyla
	// nolint:undoc
	Override string `yaml:"override" env:"BEYLA_HOST_ID"`
	// FetchTimeout specifies the timeout for trying to fetch the HostID from diverse Cloud Providers
	// nolint:undoc
	FetchTimeout time.Duration `yaml:"fetch_timeout" env:"BEYLA_HOST_ID_FETCH_TIMEOUT"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

// nolint:cyclop
func (c *Config) Validate() error {
	obiCfg := c.AsOBI()
	if err := obiCfg.Discovery.Validate(); err != nil {
		return ConfigError(err.Error())
	}

	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) {
		return ConfigError("missing application discovery section or network metrics configuration. Check documentation.")
	}
	if c.EBPF.BatchLength == 0 {
		return ConfigError("BEYLA_BPF_BATCH_LENGTH must be at least 1")
	}
	if !c.EBPF.TCBackend.Valid() {
		return ConfigError("Invalid BEYLA_BPF_TC_BACKEND value")
	}

	// nolint:staticcheck
	// remove after deleting ContextPropagationEnabled
	if c.EBPF.ContextPropagationEnabled && c.EBPF.ContextPropagation != obicfg.ContextPropagationDisabled {
		return ConfigError("context_propagation_enabled and context_propagation are mutually exclusive")
	}

	// TODO deprecated (REMOVE)
	// nolint:staticcheck
	// remove after deleting ContextPropagationEnabled
	if c.EBPF.ContextPropagationEnabled {
		slog.Warn("DEPRECATION NOTICE: 'context_propagation_enabled' configuration option has been " +
			"deprecated and will be removed in the future - use 'context_propagation' instead")
		c.EBPF.ContextPropagation = obicfg.ContextPropagationAll
	}

	if c.willUseTC() {
		if err := tcmanager.EnsureCiliumCompatibility(c.EBPF.TCBackend); err != nil {
			return ConfigError(fmt.Sprintf("Cilium compatibility error: %s", err.Error()))
		}
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

	if c.Enabled(FeatureAppO11y) && !c.TracePrinter.Enabled() &&
		!c.Grafana.OTLP.MetricsEnabled() && !c.Grafana.OTLP.TracesEnabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() &&
		!c.Prometheus.Enabled() && !c.TracePrinter.Enabled() {
		return ConfigError("you need to define at least one exporter: trace_printer," +
			" grafana, otel_metrics_export, otel_traces_export or prometheus_export")
	}

	if c.Enabled(FeatureAppO11y) &&
		((c.Prometheus.Enabled() && c.Prometheus.InvalidSpanMetricsConfig()) ||
			(c.Metrics.Enabled() && c.Metrics.InvalidSpanMetricsConfig())) {
		return ConfigError("you can only enable one format of span metrics," +
			" application_span or application_span_otel")
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

func (c *Config) willUseTC() bool {
	// nolint:staticcheck
	// remove after deleting ContextPropagationEnabled
	return c.EBPF.ContextPropagation == obicfg.ContextPropagationAll ||
		c.EBPF.ContextPropagation == obicfg.ContextPropagationIPOptionsOnly ||
		c.EBPF.ContextPropagationEnabled ||
		(c.Enabled(FeatureNetO11y) && c.NetworkFlows.Source == obi.EbpfSourceTC)
}

// Enabled checks if a given Beyla feature is enabled according to the global configuration
func (c *Config) Enabled(feature Feature) bool {
	switch feature {
	case FeatureNetO11y:
		return c.NetworkFlows.Enable || c.promNetO11yEnabled() || c.otelNetO11yEnabled()
	case FeatureAppO11y:
		return c.Port.Len() > 0 || c.AutoTargetExe.IsSet() || c.Exec.IsSet() ||
			c.Exec.IsSet() || c.Discovery.AppDiscoveryEnabled() || c.Discovery.SurveyEnabled()
	}
	return false
}

// ExternalLogger sets the logging capabilities of Beyla.
// Used for integrating Beyla with an external logging system (for example Alloy)
// TODO: maybe this method has too many responsibilities, as it affects the global logger.
func (c *Config) ExternalLogger(handler slog.Handler, debugMode bool) {
	slog.SetDefault(slog.New(handler))
	if debugMode {
		c.TracePrinter = debug.TracePrinterText
		c.EBPF.BpfDebug = true
		c.EBPF.ProtocolDebug = true
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
	OverrideOBIGlobalConfig()
	cfg := DefaultConfig()
	if file != nil {
		cfgBuf, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("reading YAML configuration: %w", err)
		}
		// replaces environment variables in YAML file
		cfgBuf = config.ReplaceEnv(cfgBuf)
		if err := yaml.Unmarshal(cfgBuf, cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML configuration: %w", err)
		}
	}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("reading env vars: %w", err)
	}

	if cfg.Discovery.SurveyEnabled() {
		cfg.Discovery.OverrideDefaultExcludeForSurvey()
	}

	return cfg, nil
}
