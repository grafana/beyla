package beyla

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/caarlos0/env/v9"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	obimeta "go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	obicfg "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v3/pkg/config"
	botel "github.com/grafana/beyla/v3/pkg/export/otel"
	"github.com/grafana/beyla/v3/pkg/export/otel/spanscfg"
	maps2 "github.com/grafana/beyla/v3/pkg/internal/helpers/maps"
	"github.com/grafana/beyla/v3/pkg/internal/infraolly/process"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

const ReporterLRUSize = 256

// Features that can be enabled in Beyla (can be at the same time): App O11y and/or Net O11y
type Feature uint

const (
	FeatureAppO11y = Feature(1 << iota)
	FeatureNetO11y
	FeatureStatsO11y
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

	def.Injector.EnabledSDKs = []servicesextra.InstrumentableType{
		{InstrumentableType: svc.InstrumentableJava},
		{InstrumentableType: svc.InstrumentableDotnet},
		{InstrumentableType: svc.InstrumentableNodejs},
		{InstrumentableType: svc.InstrumentablePython},
	}

	def.Routes.Unmatch = transform.UnmatchLowCardinality

	return def
}

type Config struct {
	EBPF obicfg.EBPFTracer `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows obi.NetworkConfig `yaml:"network"`
	// Stats configuration for Stats Observability feature
	Stats obi.StatsConfig `yaml:"stats"`

	// Grafana overrides some values of the otel.MetricsConfig and otel.TracesConfig below
	// for a simpler submission of OTEL metrics to Grafana Cloud
	Grafana botel.GrafanaConfig `yaml:"grafana"`

	Filters filter.AttributesConfig `yaml:"filter"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes       *transform.RoutesConfig       `yaml:"routes"`
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`
	OTELMetrics  otelcfg.MetricsConfig         `yaml:"otel_metrics_export"`
	Traces       otelcfg.TracesConfig          `yaml:"otel_traces_export"`
	Metrics      perapp.MetricsConfig          `yaml:"metrics"`
	Prometheus   prom.PrometheusConfig         `yaml:"prometheus_export"`
	TracePrinter debug.TracePrinter            `yaml:"trace_printer" env:"BEYLA_TRACE_PRINTER"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	// Deprecated: Use BEYLA_AUTO_TARGET_EXE
	Exec services.RegexpAttr `yaml:"executable_name" env:"BEYLA_EXECUTABLE_NAME"`

	// AutoTargetExe selects the executable to instrument matching a Glob against the executable path.
	// To set this value via YAML, use discovery > instrument.
	// It also accepts BEYLA_AUTO_TARGET_EXE for compatibility with opentelemetry-go-instrumentation
	AutoTargetExe services.GlobAttr `env:"BEYLA_AUTO_TARGET_EXE,expand" envDefault:"${OTEL_GO_AUTO_TARGET_EXE}"`

	// AutoTargetLanguage selects the executable to instrument matching a Glob of chosen languages.
	// To set this value via YAML, use discovery > instrument.
	AutoTargetLanguage services.GlobAttr `env:"BEYLA_AUTO_TARGET_LANGUAGE"`

	// TargetPIDs selects processes by PID for instrumentation. When non-empty, only these PIDs are
	// instrumented. Accepts YAML list (target_pids: [1234, 5678]), single number, or env
	// BEYLA_TARGET_PID=1234,5678. Alternative to Exec or AutoTargetExe when PIDs are known.
	TargetPIDs services.IntEnum `yaml:"target_pids" env:"BEYLA_TARGET_PID"`

	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port services.IntEnum `yaml:"open_port" env:"BEYLA_OPEN_PORT"`

	// ServiceName is taken from either BEYLA_SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility)
	// Using env and envDefault is a trick to get the value either from one of either variables.
	// Deprecated: Service name should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	ServiceName string `yaml:"service_name" env:"OTEL_SERVICE_NAME,expand" envDefault:"${BEYLA_SERVICE_NAME}"`
	// Deprecated: Service namespace should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	ServiceNamespace string `yaml:"service_namespace" env:"BEYLA_SERVICE_NAMESPACE"`

	// Discovery configuration
	Discovery servicesextra.BeylaDiscoveryConfig `yaml:"discovery"`

	LogLevel  string        `yaml:"log_level"  env:"BEYLA_LOG_LEVEL"`
	LogFormat obi.LogFormat `yaml:"log_format" env:"BEYLA_LOG_FORMAT"`

	// Timeout for a graceful shutdown
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"BEYLA_SHUTDOWN_TIMEOUT"`

	// Check for required system capabilities and bail if they are not
	// present. If set to 'false', Beyla will still print a list of missing
	// capabilities, but the execution will continue
	EnforceSysCaps bool `yaml:"enforce_sys_caps" env:"BEYLA_ENFORCE_SYS_CAPS"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen        int                            `yaml:"channel_buffer_len" env:"BEYLA_CHANNEL_BUFFER_LEN"`
	ChannelSendTimeout      time.Duration                  `yaml:"channel_send_timeout" env:"BEYLA_CHANNEL_SEND_TIMEOUT"`
	ChannelSendTimeoutPanic bool                           `yaml:"channel_send_timeout_panic" env:"BEYLA_CHANNEL_SEND_TIMEOUT_PANIC"`
	ProfilePort             int                            `yaml:"profile_port" env:"BEYLA_PROFILE_PORT"`
	InternalMetrics         imetrics.InternalMetricsConfig `yaml:"internal_metrics"`

	// Processes metrics for application. They will be only enabled if there is a metrics exporter enabled,
	// "application_process" features are enabled
	Processes process.CollectConfig `yaml:"processes"`

	// Grafana Alloy specific configuration
	TracesReceiver TracesReceiverConfig `yaml:"-"`

	// LogConfig enables the logging of the configuration on startup.
	LogConfig obi.LogConfigOption `yaml:"log_config" env:"BEYLA_LOG_CONFIG"`

	NodeJS obi.NodeJSConfig `yaml:"nodejs"`

	Java obi.JavaConfig `yaml:"javaagent"`

	// Topology enables extra topology-related features, such as inter-cluster connection spans.
	Topology spanscfg.Topology `yaml:"topology"`

	// Experimental support for OpenTelemetry SDK injection, by using the OpenTelemetry Injector
	// WARNING: This is purely experimental and undocumented feature and can be removed in the future without warning.
	Injector SDKInject `yaml:"injector"`

	// cached equivalent for the OBI conversion
	obi *obi.Config `yaml:"-"`
}

type Consumer interface {
	otelconsumer.Traces
}

type TracesReceiverConfig struct {
	Traces           []Consumer
	Sampler          services.SamplerConfig             `yaml:"sampler"`
	Instrumentations []instrumentations.Instrumentation `yaml:"instrumentations" env:"BEYLA_OTEL_TRACES_INSTRUMENTATIONS" envSeparator:","`
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
	MetadataRetry        obimeta.RetryConfig           `yaml:"metadata_retry"`

	// RenameUnresolvedHosts will replace HostName and PeerName attributes when they are empty or contain
	// unresolved IP addresses to reduce cardinality.
	// Set this value to the empty string to disable this feature.
	RenameUnresolvedHosts         string `yaml:"rename_unresolved_hosts" env:"BEYLA_RENAME_UNRESOLVED_HOSTS"`
	RenameUnresolvedHostsOutgoing string `yaml:"rename_unresolved_hosts_outgoing" env:"BEYLA_RENAME_UNRESOLVED_HOSTS_OUTGOING"`
	RenameUnresolvedHostsIncoming string `yaml:"rename_unresolved_hosts_incoming" env:"BEYLA_RENAME_UNRESOLVED_HOSTS_INCOMING"`

	// MetricSpanNameAggregationLimit works PER SERVICE and only relates to span_metrics.
	// When the span_name cardinality surpasses this limit, the span_name will be reported as AGGREGATED.
	// If the value <= 0, it is disabled.
	MetricSpanNameAggregationLimit int `yaml:"metric_span_names_limit" env:"BEYLA_METRIC_SPAN_NAMES_LIMIT"`
}

type HostIDConfig struct {
	// Override allows overriding the reported host.id in Beyla
	Override string `yaml:"override" env:"BEYLA_HOST_ID"`
}

// OpenTelemetry SDK injection for Kubernetes
// WARNING:
// This option is experimental, undocumented and might be removed in the future without warning.
// For SDK instrumentation on Kubernetes, use the OpenTelemetry Operator instead.
type SDKInject struct {
	// OTel SDK instrumentation criteria
	Instrument configmap.WebhookInstrument `yaml:"instrument"`
	// Webhook configuration for a mutating admission controller
	Webhook WebhookConfig `yaml:"webhook"`
	// Option to disable automatic bouncing of pods, it will be
	// a responsibility of the end-user to bounce the pods to be instrumented
	// TODO: move to controller?
	NoAutoRestart bool `yaml:"disable_auto_restart"`
	// OCI image mount, supported on k8s 1.31+. Must not be empty.
	ImageVolumePath string `yaml:"image_volume_path"`
	// Default sampler configuration for SDK instrumentation
	// This is used when no sampler is specified in the selector
	DefaultSampler *services.SamplerConfig `yaml:"trace_sampler"`
	// Propagators configuration for SDK instrumentation
	// Common values: tracecontext, baggage, b3, b3multi, jaeger, xray
	Propagators []string `yaml:"trace_propagators"`
	// Export configuration for SDK instrumentation
	// Controls which signals (traces, metrics, logs) should be exported from injected SDKs
	ExportedSignals configmap.SDKExportedSignals `yaml:"otel_exported_signals"`
	// Resource attributes related settings
	Resources configmap.SDKResource `yaml:"resources"`
	// List of enabled SDK auto-instrumentations. Can be used to disable specific
	// language instrumentations.
	EnabledSDKs []servicesextra.InstrumentableType `yaml:"enabled_sdks"`
}

func (s *SDKInject) Validate() error {
	if s.ImageVolumePath == "" {
		return fmt.Errorf("image volume path is required")
	}
	return nil
}

func (s *SDKInject) PackageVersion() string {
	h := sha256.Sum224([]byte(s.ImageVolumePath))
	return hex.EncodeToString(h[:]) // 56 chars, fits in 63-char label limit
}

func (s *SDKInject) UsesImageVolume() bool {
	return s.ImageVolumePath != ""
}

// WebhookConfig contains the configuration for the mutating webhook
// Functionality under active development
// TODO: most of the following options are not having effect. They must be moved to k8s-injection-controller
type WebhookConfig struct {
	// ExternalWebhook delegates the functionality of the mutating webhook to an external controller/operator
	ExternalWebhook string `yaml:"external_deployment_name" env:"BEYLA_EXTERNAL_WEBHOOK_DEPLOYMENT_NAME"`
}

func (w WebhookConfig) Enabled() bool {
	return w.ExternalWebhook != ""
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

	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) &&
		!c.Enabled(FeatureStatsO11y) && !c.Injector.Webhook.Enabled() {
		return ConfigError("missing application discovery section or network metrics configuration. Check documentation.")
	}
	if c.EBPF.BatchLength == 0 {
		return ConfigError("BEYLA_BPF_BATCH_LENGTH must be at least 1")
	}
	if !c.EBPF.TCBackend.Valid() {
		return ConfigError("Invalid BEYLA_BPF_TC_BACKEND value")
	}

	if c.willUseTC() {
		if err := tcmanager.EnsureCiliumCompatibility(c.EBPF.TCBackend); err != nil {
			return ConfigError(fmt.Sprintf("Cilium compatibility error: %s", err.Error()))
		}
	}

	if c.Attributes.Kubernetes.InformersSyncTimeout == 0 {
		return ConfigError("BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT duration must be greater than 0s")
	}

	if c.Enabled(FeatureNetO11y) && !c.Grafana.OTLP.MetricsEnabled() &&
		!c.OTELMetrics.EndpointEnabled() && !c.Prometheus.EndpointEnabled() &&
		!c.NetworkFlows.Print {
		return ConfigError("enabling network metrics requires to enable at least the OpenTelemetry" +
			" metrics exporter: grafana, otel_metrics_export or prometheus_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or BEYLA_PROMETHEUS_PORT environment variables. For debugging" +
			" purposes, you can also set BEYLA_NETWORK_PRINT_FLOWS=true")
	}

	if c.Enabled(FeatureStatsO11y) && !c.Grafana.OTLP.MetricsEnabled() &&
		!c.OTELMetrics.EndpointEnabled() && !c.Prometheus.EndpointEnabled() &&
		!c.Stats.Print {
		return ConfigError("enabling stat metrics requires to enable at least the OpenTelemetry" +
			" metrics exporter: grafana, otel_metrics_export or prometheus_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or BEYLA_PROMETHEUS_PORT environment variables. For debugging" +
			" purposes, you can also set BEYLA_STATS_PRINT_STATS=true")
	}

	if !c.TracePrinter.Valid() {
		return ConfigError(fmt.Sprintf("invalid value for trace_printer: '%s'", c.TracePrinter))
	}

	if c.Enabled(FeatureAppO11y) && !c.TracePrinter.Enabled() &&
		!c.Grafana.OTLP.MetricsEnabled() && !c.Grafana.OTLP.TracesEnabled() &&
		!c.OTELMetrics.EndpointEnabled() && !c.Traces.Enabled() &&
		!c.Prometheus.EndpointEnabled() && !c.TracePrinter.Enabled() {
		return ConfigError("you need to define at least one exporter: trace_printer," +
			" grafana, otel_metrics_export, otel_traces_export or prometheus_export")
	}

	if c.Enabled(FeatureAppO11y) &&
		c.Metrics.Features.InvalidSpanMetricsConfig() &&
		(c.Prometheus.EndpointEnabled() && c.OTELMetrics.EndpointEnabled()) {
		return ConfigError("you can only enable one format of span metrics," +
			" application_span or application_span_otel")
	}

	if c.Routes != nil && len(c.Routes.WildcardChar) > 1 {
		return ConfigError("wildcard_char can only be a single character, multiple characters are not allowed")
	}

	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && c.InternalMetrics.Prometheus.Port != 0 {
		return ConfigError("you can't enable both OTEL and Prometheus internal metrics")
	}
	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && !c.OTELMetrics.EndpointEnabled() && !c.Grafana.OTLP.MetricsEnabled() {
		return ConfigError("you can't enable OTEL internal metrics without enabling OTEL metrics")
	}

	if c.Injector.Webhook.Enabled() {
		if !c.Traces.Enabled() {
			return ConfigError("you can't enable OTEL SDK instrumentation injection without enabling OTEL traces")
		}
		proto := c.Traces.GetProtocol()
		pos := slices.IndexFunc([]otelcfg.Protocol{otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, otelcfg.ProtocolGRPC, ""}, func(p otelcfg.Protocol) bool {
			return p == proto
		})
		if pos < 0 {
			return ConfigError(fmt.Sprintf("unsupported OTEL traces export protocol %s", proto))
		}

		if err := c.Injector.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) promNetO11yEnabled() bool {
	return c.Prometheus.EndpointEnabled() && c.Metrics.Features.AnyNetwork()
}

func (c *Config) otelNetO11yEnabled() bool {
	return (c.OTELMetrics.EndpointEnabled() || c.Grafana.OTLP.MetricsEnabled()) && c.Metrics.Features.AnyNetwork()
}

func (c *Config) promStatsO11yEnabled() bool {
	return c.Prometheus.EndpointEnabled() && c.Metrics.Features.StatMetrics()
}

func (c *Config) otelStatsO11yEnabled() bool {
	return (c.OTELMetrics.EndpointEnabled() || c.Grafana.OTLP.MetricsEnabled()) && c.Metrics.Features.StatMetrics()
}

func (c *Config) willUseTC() bool {
	// nolint:staticcheck
	// remove after deleting ContextPropagationEnabled
	return c.EBPF.ContextPropagation == obicfg.ContextPropagationAll ||
		c.EBPF.ContextPropagation == obicfg.ContextPropagationTCP ||
		(c.Enabled(FeatureNetO11y) && c.NetworkFlows.Source == obi.EbpfSourceTC)
}

// Enabled checks if a given Beyla feature is enabled according to the global configuration
func (c *Config) appO11yEnabled() bool {
	return c.Port.Len() > 0 || c.AutoTargetExe.IsSet() || c.AutoTargetLanguage.IsSet() || c.Exec.IsSet() ||
		c.Exec.IsSet() || c.Discovery.AppDiscoveryEnabled() || c.Discovery.SurveyEnabled()
}

func (c *Config) Enabled(feature Feature) bool {
	switch feature {
	case FeatureNetO11y:
		return c.NetworkFlows.Enable || c.promNetO11yEnabled() || c.otelNetO11yEnabled()
	case FeatureAppO11y:
		return c.appO11yEnabled()
	case FeatureStatsO11y:
		return c.promStatsO11yEnabled() || c.otelStatsO11yEnabled()
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
	cfg := *DefaultConfig()
	if file != nil {
		cfgBuf, err := io.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("reading YAML configuration: %w", err)
		}
		// replaces environment variables in YAML file
		cfgBuf = config.ReplaceEnv(cfgBuf)
		if err := yaml.Unmarshal(cfgBuf, &cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML configuration: %w", err)
		}
	}
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("reading env vars: %w", err)
	}
	normalizeConfig(&cfg)
	return &cfg, nil
}

// normalizeConfig normalizes user input to a common set of assumptions that are global to Beyla/OBI
// TODO: this replicates a private function in OBI repo. We should make it public and invoke it here instead.
func normalizeConfig(c *Config) {
	if c.Discovery.SurveyEnabled() {
		c.Discovery.OverrideDefaultExcludeForSurvey()
	}
	c.Attributes.Select.Normalize()
	// backwards compatibility assumptions for the deprecated Metric feature sections in OTEL and Prom metrics config.
	// Old, deprecated properties would take precedence over metrics > features, to avoid breaking changes.
	if c.OTELMetrics.EndpointEnabled() && c.OTELMetrics.DeprFeatures != 0 {
		// if the user has overridden otel_metrics_export > features
		c.Metrics.Features = c.OTELMetrics.DeprFeatures
	} else if c.Prometheus.EndpointEnabled() && c.Prometheus.DeprFeatures != 0 {
		// if the user has overridden prometheus_export > features
		c.Metrics.Features = c.Prometheus.DeprFeatures
	}
	// Deprecated: to be removed together with OTEL_EBPF_NETWORK_METRICS bool flag
	if c.NetworkFlows.Enable {
		c.Metrics.Features |= export.FeatureNetwork
	}

	c.OTELMetrics.ExtraSpanResourceLabels = appendDefaultResourceLabels(c.OTELMetrics.ExtraSpanResourceLabels)
	c.Prometheus.ExtraSpanResourceLabels = appendDefaultResourceLabels(c.Prometheus.ExtraSpanResourceLabels)
}

func appendDefaultResourceLabels(dst []string) []string {
	// appends mandatory resource labels to a slice and deduplicates it
	return maps2.SetToSlice(maps2.SliceToSet(append(dst,
		string(attr.K8sClusterName),
		string(attr.K8sNamespaceName),
		string(attr.K8sNodeName),
		string(semconv.ServiceVersionKey),
		string(semconv.DeploymentEnvironmentNameKey),
		string(semconv.CloudAvailabilityZoneKey),
		string(semconv.CloudRegionKey))))
}
