package beyla

import (
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"time"

	"github.com/caarlos0/env/v9"
	"github.com/gobwas/glob"
	"gopkg.in/yaml.v3"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/tcmanager"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/traces"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/config"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/debug"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/instrumentations"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/otel"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/prom"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/filter"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubeflags"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/transform"
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

const (
	k8sGKEDefaultNamespacesRegex = "|^gke-connect$|^gke-gmp-system$|^gke-managed-cim$|^gke-managed-filestorecsi$|^gke-managed-metrics-server$|^gke-managed-system$|^gke-system$|^gke-managed-volumepopulator$"
	k8sGKEDefaultNamespacesGlob  = ",gke-connect,gke-gmp-system,gke-managed-cim,gke-managed-filestorecsi,gke-managed-metrics-server,gke-managed-system,gke-system,gke-managed-volumepopulator"
)

const (
	k8sAKSDefaultNamespacesRegex = "|^gatekeeper-system"
	k8sAKSDefaultNamespacesGlob  = ",gatekeeper-system"
)

var (
	k8sDefaultNamespacesRegex = services.NewPathRegexp(regexp.MustCompile("^kube-system$|^kube-node-lease$|^local-path-storage$|^grafana-alloy$|^cert-manager$|^monitoring$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex))
	k8sDefaultNamespacesGlob  = services.NewGlob(glob.MustCompile("{kube-system,kube-node-lease,local-path-storage,grafana-alloy,cert-manager,monitoring" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}"))
)

var DefaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	ShutdownTimeout:  10 * time.Second,
	EnforceSysCaps:   false,
	EBPF: config.EBPFTracer{
		BatchLength:               100,
		BatchTimeout:              time.Second,
		HTTPRequestTimeout:        0,
		TCBackend:                 tcmanager.TCBackendAuto,
		ContextPropagationEnabled: false,
		ContextPropagation:        config.ContextPropagationDisabled,
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
			ResourceLabels:        kube.DefaultResourceLabels,
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
	Discovery: services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
		DefaultExcludeServices: services.RegexDefinitionCriteria{
			services.RegexSelector{
				Path: services.NewPathRegexp(regexp.MustCompile("(?:^|/)(beyla$|alloy$|otelcol[^/]*$)")),
			},
			services.RegexSelector{
				Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &k8sDefaultNamespacesRegex},
			},
		},
		DefaultExcludeInstrument: services.GlobDefinitionCriteria{
			services.GlobAttributes{
				Path: services.NewGlob(glob.MustCompile("{*beyla,*alloy,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}")),
			},
			services.GlobAttributes{
				Metadata: map[string]*services.GlobAttr{"k8s_namespace": &k8sDefaultNamespacesGlob},
			},
		},
	},
}

type Config struct {
	EBPF config.EBPFTracer `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows NetworkConfig `yaml:"network"`

	Filters filter.AttributesConfig `yaml:"filter"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes *transform.RoutesConfig `yaml:"routes"`
	//nolint:undoc
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`
	Metrics      otel.MetricsConfig            `yaml:"otel_metrics_export"`
	Traces       otel.TracesConfig             `yaml:"otel_traces_export"`
	Prometheus   prom.PrometheusConfig         `yaml:"prometheus_export"`
	TracePrinter debug.TracePrinter            `yaml:"trace_printer" env:"OTEL_EBPF_TRACE_PRINTER"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	// Deprecated: Use OTEL_EBPF_AUTO_TARGET_EXE
	Exec services.RegexpAttr `yaml:"executable_path" env:"OTEL_EBPF_EXECUTABLE_PATH"`

	// AutoTargetExe selects the executable to instrument matching a Glob against the executable path.
	// To set this value via YAML, use discovery > instrument.
	// It also accepts OTEL_GO_AUTO_TARGET_EXE for compatibility with opentelemetry-go-instrumentation
	//nolint:undoc
	AutoTargetExe services.GlobAttr `env:"OTEL_EBPF_AUTO_TARGET_EXE,expand" envDefault:"${OTEL_GO_AUTO_TARGET_EXE}"`

	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port services.PortEnum `yaml:"open_port" env:"OTEL_EBPF_OPEN_PORT"`

	// ServiceName is taken from either OTEL_EBPF_SERVICE_NAME env var or OTEL_SERVICE_NAME (for OTEL spec compatibility)
	// Using env and envDefault is a trick to get the value either from one of either variables.
	// Deprecated: Service name should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	ServiceName string `yaml:"service_name" env:"OTEL_SERVICE_NAME,expand" envDefault:"${OTEL_EBPF_SERVICE_NAME}"`
	// Deprecated: Service namespace should be set in the instrumentation target (env vars, kube metadata...)
	// as this is a reminiscence of past times when we only supported one executable per instance.
	ServiceNamespace string `yaml:"service_namespace" env:"OTEL_EBPF_SERVICE_NAMESPACE"`

	// Discovery configuration
	Discovery services.DiscoveryConfig `yaml:"discovery"`

	LogLevel string `yaml:"log_level" env:"OTEL_EBPF_LOG_LEVEL"`

	// Timeout for a graceful shutdown
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"OTEL_EBPF_SHUTDOWN_TIMEOUT"`

	// Check for required system capabilities and bail if they are not
	// present. If set to 'false', Beyla will still print a list of missing
	// capabilities, but the execution will continue
	EnforceSysCaps bool `yaml:"enforce_sys_caps" env:"OTEL_EBPF_ENFORCE_SYS_CAPS"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	//nolint:undoc
	ChannelBufferLen int `yaml:"channel_buffer_len" env:"OTEL_EBPF_CHANNEL_BUFFER_LEN"`
	//nolint:undoc
	ProfilePort     int             `yaml:"profile_port" env:"OTEL_EBPF_PROFILE_PORT"`
	InternalMetrics imetrics.Config `yaml:"internal_metrics"`
}

// Attributes configures the decoration of some extra attributes that will be
// added to each span
type Attributes struct {
	Kubernetes           transform.KubernetesDecorator `yaml:"kubernetes"`
	InstanceID           traces.InstanceIDConfig       `yaml:"instance_id"`
	Select               attributes.Selection          `yaml:"select"`
	HostID               HostIDConfig                  `yaml:"host_id"`
	ExtraGroupAttributes map[string][]attr.Name        `yaml:"extra_group_attributes"`
}

type HostIDConfig struct {
	// Override allows overriding the reported host.id in Beyla
	//nolint:undoc
	Override string `yaml:"override" env:"OTEL_EBPF_HOST_ID"`
	// FetchTimeout specifies the timeout for trying to fetch the HostID from diverse Cloud Providers
	//nolint:undoc
	FetchTimeout time.Duration `yaml:"fetch_timeout" env:"OTEL_EBPF_HOST_ID_FETCH_TIMEOUT"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

// Validate configuration
//
//nolint:cyclop
func (c *Config) Validate() error {
	if err := c.Discovery.Validate(); err != nil {
		return ConfigError(err.Error())
	}

	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) {
		return ConfigError("missing to enable application discovery or network metrics. Check documentation")
	}
	if c.EBPF.BatchLength == 0 {
		return ConfigError("OTEL_EBPF_BPF_BATCH_LENGTH must be at least 1")
	}
	if !c.EBPF.TCBackend.Valid() {
		return ConfigError("Invalid OTEL_EBPF_BPF_TC_BACKEND value")
	}

	// remove after deleting ContextPropagationEnabled
	if c.EBPF.ContextPropagationEnabled && c.EBPF.ContextPropagation != config.ContextPropagationDisabled {
		return ConfigError("context_propagation_enabled and context_propagation are mutually exclusive")
	}

	// TODO deprecated (REMOVE)
	// remove after deleting ContextPropagationEnabled
	if c.EBPF.ContextPropagationEnabled {
		slog.Warn("DEPRECATION NOTICE: 'context_propagation_enabled' configuration option has been " +
			"deprecated and will be removed in the future - use 'context_propagation' instead")
		c.EBPF.ContextPropagation = config.ContextPropagationAll
	}

	if c.willUseTC() {
		if err := tcmanager.EnsureCiliumCompatibility(c.EBPF.TCBackend); err != nil {
			return ConfigError("Cilium compatibility error: " + err.Error())
		}
	}

	if c.Attributes.Kubernetes.InformersSyncTimeout == 0 {
		return ConfigError("OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT duration must be greater than 0s")
	}

	if c.Enabled(FeatureNetO11y) && !c.Metrics.Enabled() &&
		!c.Prometheus.Enabled() && !c.NetworkFlows.Print {
		return ConfigError("enabling network metrics requires to enable at least the OpenTelemetry" +
			" metrics exporter: otel_metrics_export or prometheus_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or OTEL_EBPF_PROMETHEUS_PORT environment variables. For debugging" +
			" purposes, you can also set OTEL_EBPF_NETWORK_PRINT_FLOWS=true")
	}

	if !c.TracePrinter.Valid() {
		return ConfigError(fmt.Sprintf("invalid value for trace_printer: '%s'", c.TracePrinter))
	}

	if c.Enabled(FeatureAppO11y) && !c.TracePrinter.Enabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() &&
		!c.Prometheus.Enabled() && !c.TracePrinter.Enabled() {
		return ConfigError("you need to define at least one exporter: trace_printer," +
			" otel_metrics_export, otel_traces_export or prometheus_export")
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
	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && !c.Metrics.Enabled() {
		return ConfigError("you can't enable OTEL internal metrics without enabling OTEL metrics")
	}

	return nil
}

func (c *Config) promNetO11yEnabled() bool {
	return c.Prometheus.Enabled() && c.Prometheus.NetworkMetricsEnabled()
}

func (c *Config) otelNetO11yEnabled() bool {
	return c.Metrics.Enabled() && c.Metrics.NetworkMetricsEnabled()
}

func (c *Config) willUseTC() bool {
	// remove after deleting ContextPropagationEnabled
	return c.EBPF.ContextPropagation == config.ContextPropagationAll ||
		c.EBPF.ContextPropagation == config.ContextPropagationIPOptionsOnly ||
		c.EBPF.ContextPropagationEnabled ||
		(c.Enabled(FeatureNetO11y) && c.NetworkFlows.Source == EbpfSourceTC)
}

// Enabled checks if a given Beyla feature is enabled according to the global configuration
func (c *Config) Enabled(feature Feature) bool {
	switch feature {
	case FeatureNetO11y:
		return c.NetworkFlows.Enable || c.promNetO11yEnabled() || c.otelNetO11yEnabled()
	case FeatureAppO11y:
		return c.Port.Len() > 0 || c.AutoTargetExe.IsSet() || len(c.Discovery.Instrument) > 0 ||
			c.Exec.IsSet() || len(c.Discovery.Services) > 0
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
	cfg := DefaultConfig
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

	return &cfg, nil
}
