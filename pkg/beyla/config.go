package beyla

import (
	"fmt"
	"io"
	"log/slog"
	"slices"
	"time"

	"github.com/caarlos0/env/v9"
	otelconsumer "go.opentelemetry.io/collector/consumer"
	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
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
	"github.com/grafana/beyla/v3/pkg/internal/infraolly/process"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
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
	def.Injector.Webhook = WebhookConfig{
		Enable:   false,
		Port:     8443,
		Timeout:  30 * time.Second,
		CertPath: "/etc/webhook/certs/tls.crt",
		KeyPath:  "/etc/webhook/certs/tls.key",
	}
	def.Injector.HostPathVolumeDir = "/var/lib/beyla/instrumentation"
	def.Injector.ManageSDKVersions = true
	def.Injector.EnabledSDKs = []servicesextra.InstrumentableType{
		{InstrumentableType: svc.InstrumentableJava},
		{InstrumentableType: svc.InstrumentableDotnet},
		{InstrumentableType: svc.InstrumentableNodejs},
	}

	if !slices.Contains(def.OTELMetrics.ExtraSpanResourceLabels, "k8s.namespace.name") {
		def.OTELMetrics.ExtraSpanResourceLabels = append(def.OTELMetrics.ExtraSpanResourceLabels, "k8s.namespace.name")
	}
	if !slices.Contains(def.Prometheus.ExtraSpanResourceLabels, "k8s.namespace.name") {
		def.Prometheus.ExtraSpanResourceLabels = append(def.Prometheus.ExtraSpanResourceLabels, "k8s.namespace.name")
	}
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
	OTELMetrics  otelcfg.MetricsConfig         `yaml:"otel_metrics_export"`
	Traces       otelcfg.TracesConfig          `yaml:"otel_traces_export"`
	Metrics      perapp.MetricsConfig          `yaml:"metrics"`
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
	ChannelSendTimeout time.Duration `yaml:"channel_send_timeout" env:"BEYLA_CHANNEL_SEND_TIMEOUT"`
	// nolint:undoc
	ChannelSendTimeoutPanic bool `yaml:"channel_send_timeout_panic" env:"BEYLA_CHANNEL_SEND_TIMEOUT_PANIC"`
	// nolint:undoc
	ProfilePort     int             `yaml:"profile_port" env:"BEYLA_PROFILE_PORT"`
	InternalMetrics imetrics.Config `yaml:"internal_metrics"`

	// Processes metrics for application. They will be only enabled if there is a metrics exporter enabled,
	// "application_process" features are enabled
	Processes process.CollectConfig `yaml:"processes"`

	// Grafana Alloy specific configuration
	TracesReceiver TracesReceiverConfig `yaml:"-"`

	// LogConfig enables the logging of the configuration on startup.
	// nolint:undoc
	LogConfig obi.LogConfigOption `yaml:"log_config" env:"BEYLA_LOG_CONFIG"`

	// nolint:undoc
	NodeJS obi.NodeJSConfig `yaml:"nodejs"`

	// nolint:undoc
	Java obi.JavaConfig `yaml:"javaagent"`

	// Topology enables extra topology-related features, such as inter-cluster connection spans.
	// nolint:undoc
	Topology spanscfg.Topology `yaml:"topology"`

	// Experimental support for OpenTelemetry SDK injection, by using the OpenTelemetry Injector
	// WARNING: This is purely experimental and undocumented feature and can be removed in the future without warning.
	// nolint:undoc
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

// OpenTelemetry SDK injection for Kubernetes
// WARNING:
// This option is experimental, undocumented and might be removed in the future without warning.
// For SDK instrumentation on Kubernetes, use the OpenTelemetry Operator instead.
type SDKInject struct {
	// OTel SDK instrumentation criteria
	// nolint:undoc
	Instrument services.GlobDefinitionCriteria `yaml:"instrument"`
	// Webhook configuration for a mutating admission controller
	// nolint:undoc
	Webhook WebhookConfig `yaml:"webhook"`
	// Option to disable automatic bouncing of pods, it will be
	// a responsibility of the end-user to bounce the pods to be instrumented
	// nolint:undoc
	NoAutoRestart bool `yaml:"disable_auto_restart"`
	// The host path volume directory which gets mounted into pods
	// nolint:undoc
	HostPathVolumeDir string `yaml:"host_path_volume"`
	// The mutator will set the version on pods if this value is set
	// This is used to let Beyla upgrade already instrumented services
	// If the version doesn't match we still bounce existing pods
	// nolint:undoc
	SDKPkgVersion string `yaml:"sdk_package_version"`
	// The host mount path where the SDK copy init container copies the files.
	// This is the root path, sdk_version is appended on top
	// nolint:undoc
	HostMountPath string `yaml:"host_mount_path"`
	// Tells Beyla that it should delete old SDK versions on the
	// host mount volume. Default true.
	// nolint:undoc
	ManageSDKVersions bool `yaml:"manage_sdk_versions"`
	// Default sampler configuration for SDK instrumentation
	// This is used when no sampler is specified in the selector
	// nolint:undoc
	DefaultSampler *services.SamplerConfig `yaml:"sampler"`
	// Propagators configuration for SDK instrumentation
	// Common values: tracecontext, baggage, b3, b3multi, jaeger, xray
	// nolint:undoc
	Propagators []string `yaml:"propagators"`
	// Export configuration for SDK instrumentation
	// Controls which signals (traces, metrics, logs) should be exported from injected SDKs
	// nolint:undoc
	Export SDKExport `yaml:"export"`
	// Resource attributes related settings
	// nolint:undoc
	Resources SDKResource `yaml:"resources"`
	// List of enabled SDK auto-instrumentations. Can be used to disable specific
	// language instrumentations.
	// nolint:undoc
	EnabledSDKs []servicesextra.InstrumentableType `yaml:"enabled_sdks"`
}

// SDKExport defines which telemetry signals should be exported from injected SDKs.
// These settings are independent from the global export configuration and allow
// the injector to export metrics/traces/logs even when Beyla uses Prometheus for metrics.
type SDKExport struct {
	// Traces enables trace export from injected SDKs via OTLP
	// Defaults to true (enabled) when not explicitly set
	// nolint:undoc
	Traces *bool `yaml:"traces" env:"BEYLA_SDK_EXPORT_TRACES"`
	// Metrics enables metric export from injected SDKs via OTLP
	// Defaults to true (enabled) when not explicitly set
	// Note: SDKs can only export via OTLP, not Prometheus scraping
	// nolint:undoc
	Metrics *bool `yaml:"metrics" env:"BEYLA_SDK_EXPORT_METRICS"`
	// Logs enables log export from injected SDKs via OTLP
	// Defaults to false (disabled) when not explicitly set
	// nolint:undoc
	Logs *bool `yaml:"logs" env:"BEYLA_SDK_EXPORT_LOGS"`
}

// TracesEnabled returns whether trace export is enabled for SDK instrumentation
// Defaults to true when not explicitly set
func (e SDKExport) TracesEnabled() bool {
	if e.Traces == nil {
		return true // default to enabled
	}
	return *e.Traces
}

// MetricsEnabled returns whether metric export is enabled for SDK instrumentation
// Defaults to true when not explicitly set
func (e SDKExport) MetricsEnabled() bool {
	if e.Metrics == nil {
		return true // default to enabled
	}
	return *e.Metrics
}

// LogsEnabled returns whether log export is enabled for SDK instrumentation
// Defaults to false when not explicitly set
func (e SDKExport) LogsEnabled() bool {
	if e.Logs == nil {
		return false // default to disabled
	}
	return *e.Logs
}

// Resource defines the configuration for the resource attributes, as defined by the OpenTelemetry specification.
// See also: https://github.com/open-telemetry/opentelemetry-specification/blob/v1.8.0/specification/overview.md#resources
type SDKResource struct {
	// Attributes defines attributes that are added to the resource.
	// For example environment: dev
	// +optional
	// nolint:undoc
	Attributes map[string]string `yaml:"resourceAttributes" env:"BEYLA_RESOURCE_ATTRIBUTES"`

	// AddK8sUIDAttributes defines whether K8s UID attributes should be collected (e.g. k8s.deployment.uid).
	// +optional
	// nolint:undoc
	AddK8sUIDAttributes bool `yaml:"addK8sUIDAttributes" env:"BEYLA_RESOURCE_ADD_K8S_UID_ATTRIBUTES"`

	// UseLabelsForResourceAttributes defines whether to use common labels for resource attributes:
	// Note: first entry wins:
	//   - `app.kubernetes.io/instance` becomes `service.name`
	//   - `app.kubernetes.io/name` becomes `service.name`
	//   - `app.kubernetes.io/version` becomes `service.version`
	// nolint:undoc
	UseLabelsForResourceAttributes bool `yaml:"useLabelsForResourceAttributes,omitempty" env:"BEYLA_RESOURCE_USE_LABELS_FOR_RESOURCE_ATTRIBUTES"`
}

// WebhookConfig contains the configuration for the mutating webhook
type WebhookConfig struct {
	// Enable enables the mutating webhook server
	// nolint:undoc
	Enable bool `yaml:"enable" env:"BEYLA_WEBHOOK_ENABLE"`
	// Port is the port the webhook server listens on
	// nolint:undoc
	Port int `yaml:"port" env:"BEYLA_WEBHOOK_LISTEN_PORT"`
	// CertPath is the path to the TLS certificate file
	// nolint:undoc
	CertPath string `yaml:"cert_path" env:"BEYLA_WEBHOOK_CERT_PATH"`
	// KeyPath is the path to the TLS key file
	// nolint:undoc
	KeyPath string `yaml:"key_path" env:"BEYLA_WEBHOOK_KEY_PATH"`
	// Timeout is the time we wait for the TLS webhook to get initialized
	// nolint:undoc
	Timeout time.Duration `yaml:"timeout" env:"BEYLA_WEBHOOK_TIMEOUT"`
}

func (w WebhookConfig) Enabled() bool {
	return w.Enable && w.Port > 0 && w.CertPath != "" && w.KeyPath != ""
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

	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) && !c.Injector.Webhook.Enabled() {
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

		if c.Injector.SDKPkgVersion == "" {
			return ConfigError("sdk_package_version must be supplied for the Injector component and this version must match the version used in the SDK init container")
		} else if !semver.IsValid(c.Injector.SDKPkgVersion) {
			return ConfigError("sdk_package_version must be in valid semantic versioning format, e.g. v0.0.1 (the v prefix is required)")
		}

		if c.Injector.HostMountPath == "" {
			return ConfigError("host_mount_path must be supplied for the Injector component otherwise we cannot clean-up stale SDK versions")
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

func (c *Config) willUseTC() bool {
	// nolint:staticcheck
	// remove after deleting ContextPropagationEnabled
	return c.EBPF.ContextPropagation == obicfg.ContextPropagationAll ||
		c.EBPF.ContextPropagation == obicfg.ContextPropagationIPOptions ||
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
}
