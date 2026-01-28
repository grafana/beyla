// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"encoding"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/caarlos0/env/v9"
	"github.com/go-playground/validator/v10"
	"github.com/go-viper/mapstructure/v2"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/collector/confmap"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/tcmanager"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/transform"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "DEBUG"
	LogLevelInfo  LogLevel = "INFO"
	LogLevelWarn  LogLevel = "WARN"
	LogLevelError LogLevel = "ERROR"
)

// CustomValidations is a map of tag:function for custom validations
type CustomValidations map[string]validator.Func

const (
	validationTagAgentIPIface = "agentIPIface"
)

const ReporterLRUSize = 256

// Features that can be enabled in OBI (can be at the same time): App O11y and/or Net O11y
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
	k8sDefaultNamespacesRegex = services.NewRegexp("^kube-system$|^kube-node-lease$|^local-path-storage$|^grafana-alloy$|^cert-manager$|^monitoring$" + k8sGKEDefaultNamespacesRegex + k8sAKSDefaultNamespacesRegex)
	k8sDefaultNamespacesGlob  = services.NewGlob("{kube-system,kube-node-lease,local-path-storage,grafana-alloy,cert-manager,monitoring" + k8sGKEDefaultNamespacesGlob + k8sAKSDefaultNamespacesGlob + "}")
)

var DefaultConfig = Config{
	ChannelBufferLen:        50,
	ChannelSendTimeout:      time.Minute,
	ChannelSendTimeoutPanic: false,
	LogLevel:                LogLevelInfo,
	ShutdownTimeout:         10 * time.Second,
	EnforceSysCaps:          false,
	EBPF: config.EBPFTracer{
		BatchLength:        100,
		BatchTimeout:       time.Second,
		HTTPRequestTimeout: 0,
		TCBackend:          config.TCBackendAuto,
		DNSRequestTimeout:  5 * time.Second,
		ContextPropagation: config.ContextPropagationDisabled,
		RedisDBCache: config.RedisDBCacheConfig{
			Enabled: false,
			MaxSize: 1000,
		},
		BufferSizes: config.EBPFBufferSizes{
			HTTP:     0,
			MySQL:    0,
			Postgres: 0,
			Kafka:    0,
		},
		MySQLPreparedStatementsCacheSize:    1024,
		PostgresPreparedStatementsCacheSize: 1024,
		MongoRequestsCacheSize:              1024,
		KafkaTopicUUIDCacheSize:             1024,
		CouchbaseDBCacheSize:                1024,
		OverrideBPFLoopEnabled:              false,
		PayloadExtraction: config.PayloadExtraction{
			HTTP: config.HTTPConfig{
				GraphQL: config.GraphQLConfig{
					Enabled: false,
				},
				Elasticsearch: config.ElasticsearchConfig{
					Enabled: false,
				},
				AWS: config.AWSConfig{
					Enabled: false,
				},
			},
		},
		MaxTransactionTime: 5 * time.Minute,
		LogEnricher: config.LogEnricherConfig{
			CacheTTL:              30 * time.Minute,
			CacheSize:             128,
			AsyncWriterWorkers:    8,
			AsyncWriterChannelLen: 500,
		},
	},
	NameResolver: &transform.NameResolverConfig{
		Sources:  []transform.Source{transform.SourceK8s},
		CacheLen: 1024,
		CacheTTL: 5 * time.Minute,
	},
	Metrics: perapp.MetricsConfig{
		Features: export.FeatureApplicationRED,
	},
	OTELMetrics: otelcfg.MetricsConfig{
		Protocol:        otelcfg.ProtocolUnset,
		MetricsProtocol: otelcfg.ProtocolUnset,
		// Matches Alloy and Grafana recommended scrape interval
		OTELIntervalMS:       60_000,
		Buckets:              export.DefaultBuckets,
		ReportersCacheLen:    ReporterLRUSize,
		HistogramAggregation: otel.AggregationExplicit,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationALL,
		},
		TTL: defaultMetricsTTL,
	},
	Traces: otelcfg.TracesConfig{
		Protocol:          otelcfg.ProtocolUnset,
		TracesProtocol:    otelcfg.ProtocolUnset,
		MaxQueueSize:      4096,
		BatchTimeout:      15 * time.Second,
		ReportersCacheLen: ReporterLRUSize,
		Instrumentations: []instrumentations.Instrumentation{
			instrumentations.InstrumentationHTTP,
			instrumentations.InstrumentationGRPC,
			instrumentations.InstrumentationSQL,
			instrumentations.InstrumentationRedis,
			instrumentations.InstrumentationKafka,
			instrumentations.InstrumentationMQTT,
			instrumentations.InstrumentationMongo,
			// no traces for DNS and GPU by default
		},
	},
	Prometheus: prom.PrometheusConfig{
		Path:    "/metrics",
		Buckets: export.DefaultBuckets,
		Instrumentations: []instrumentations.Instrumentation{
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
		BpfMetricScrapeInterval: 15 * time.Second,
	},
	Attributes: Attributes{
		InstanceID: config.InstanceIDConfig{
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
		RenameUnresolvedHosts:          "unresolved",
		RenameUnresolvedHostsOutgoing:  "outgoing",
		RenameUnresolvedHostsIncoming:  "incoming",
		MetricSpanNameAggregationLimit: 100,
	},
	Routes: &transform.RoutesConfig{
		Unmatch:                   transform.UnmatchDefault,
		WildcardChar:              "*",
		MaxPathSegmentCardinality: 10,
	},
	NetworkFlows: DefaultNetworkConfig,
	Discovery: services.DiscoveryConfig{
		ExcludeOTelInstrumentedServices: true,
		DefaultExcludeServices: services.RegexDefinitionCriteria{
			services.RegexSelector{
				Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|otelcol[^/]*$)"),
			},
			services.RegexSelector{
				Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &k8sDefaultNamespacesRegex},
			},
		},
		DefaultExcludeInstrument: services.GlobDefinitionCriteria{
			services.GlobAttributes{
				Path: services.NewGlob("{*beyla,*alloy,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
			},
			services.GlobAttributes{
				Metadata: map[string]*services.GlobAttr{"k8s_namespace": &k8sDefaultNamespacesGlob},
			},
		},
		MinProcessAge:         5 * time.Second,
		DefaultOtlpGRPCPort:   4317,
		RouteHarvesterTimeout: 10 * time.Second,
		RouteHarvestConfig: services.RouteHarvestingConfig{
			JavaHarvestDelay: 60 * time.Second,
		},
	},
	NodeJS: NodeJSConfig{
		Enabled: true,
	},
	Java: JavaConfig{
		Enabled: true,
		Timeout: 10 * time.Second,
	},
}

type Config struct {
	EBPF config.EBPFTracer `yaml:"ebpf"`

	// NetworkFlows configuration for Network Observability feature
	NetworkFlows NetworkConfig `yaml:"network"`

	Filters filter.AttributesConfig `yaml:"filter"`

	Attributes Attributes `yaml:"attributes"`
	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes       *transform.RoutesConfig       `yaml:"routes"`
	NameResolver *transform.NameResolverConfig `yaml:"name_resolver"`
	OTELMetrics  otelcfg.MetricsConfig         `yaml:"otel_metrics_export"`
	Traces       otelcfg.TracesConfig          `yaml:"otel_traces_export"`
	Prometheus   prom.PrometheusConfig         `yaml:"prometheus_export"`
	TracePrinter debug.TracePrinter            `yaml:"trace_printer" env:"OTEL_EBPF_TRACE_PRINTER"`

	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	// Deprecated: Use OTEL_EBPF_AUTO_TARGET_EXE
	Exec services.RegexpAttr `yaml:"executable_path" env:"OTEL_EBPF_EXECUTABLE_PATH"`

	// AutoTargetExe selects the executable to instrument matching a Glob against the executable path.
	// To set this value via YAML, use discovery > instrument.
	// It also accepts OTEL_GO_AUTO_TARGET_EXE for compatibility with opentelemetry-go-instrumentation
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

	// Metrics is a placeholder for the progressive support of the OTEL declarative configuration.
	Metrics perapp.MetricsConfig `yaml:"metrics"`

	// Discovery configuration
	Discovery services.DiscoveryConfig `yaml:"discovery"`

	LogLevel LogLevel `yaml:"log_level" env:"OTEL_EBPF_LOG_LEVEL"`

	// Timeout for a graceful shutdown
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"OTEL_EBPF_SHUTDOWN_TIMEOUT"`

	// Check for required system capabilities and bail if they are not
	// present. If set to 'false', OBI will still print a list of missing
	// capabilities, but the execution will continue
	EnforceSysCaps bool `yaml:"enforce_sys_caps" env:"OTEL_EBPF_ENFORCE_SYS_CAPS"`

	// From this comment, the properties below will remain undocumented, as they
	// are useful for development purposes. They might be helpful for customer support.

	ChannelBufferLen        int           `yaml:"channel_buffer_len" env:"OTEL_EBPF_CHANNEL_BUFFER_LEN"`
	ChannelSendTimeout      time.Duration `yaml:"channel_send_timeout" env:"OTEL_EBPF_CHANNEL_SEND_TIMEOUT"`
	ChannelSendTimeoutPanic bool          `yaml:"channel_send_timeout_panic" env:"OTEL_EBPF_CHANNEL_SEND_TIMEOUT_PANIC"`

	ProfilePort     int             `yaml:"profile_port" env:"OTEL_EBPF_PROFILE_PORT"`
	InternalMetrics imetrics.Config `yaml:"internal_metrics"`

	// LogConfig enables the logging of the configuration on startup.
	LogConfig LogConfigOption `yaml:"log_config" env:"OTEL_EBPF_LOG_CONFIG"`

	NodeJS NodeJSConfig `yaml:"nodejs"`
	Java   JavaConfig   `yaml:"javaagent"`
}

func (c *Config) Unmarshal(component *confmap.Conf) error {
	if component == nil {
		return nil
	}

	raw := component.ToStringMap()

	dec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		TagName:          "yaml",
		Result:           c,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.TextUnmarshallerHookFunc(),
			stringSliceToTextUnmarshalerHookFunc(),
			inlineMetadataHookFunc(),
		),
	})
	if err != nil {
		return err
	}

	return dec.Decode(raw)
}

func (c *Config) Log() {
	if c.LogConfig == "" {
		return
	}
	var configString string
	configYaml, err := yaml.Marshal(c)
	if err != nil {
		slog.Warn("can't marshal configuration to YAML", "error", err)
		return
	}
	switch c.LogConfig {
	case LogConfigOptionYAML:
		configString = string(configYaml)
	case LogConfigOptionJSON:
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

// stringSliceToTextUnmarshalerHookFunc returns a DecodeHookFunc that converts
// slices of strings (or []interface{} containing strings) to types implementing
// encoding.TextUnmarshaler by joining them with commas.
// This handles types like Features and ExportModes that have UnmarshalYAML for
// YAML sequences but also support comma-separated text via UnmarshalText.
func stringSliceToTextUnmarshalerHookFunc() mapstructure.DecodeHookFunc {
	return func(_ reflect.Type, to reflect.Type, data any) (any, error) {
		// Check if target implements TextUnmarshaler
		if to.Kind() == reflect.Ptr {
			to = to.Elem()
		}
		toPtr := reflect.New(to)
		if _, ok := toPtr.Interface().(encoding.TextUnmarshaler); !ok {
			return data, nil
		}

		if slice, ok := data.([]any); ok {
			strs := make([]string, 0, len(slice))
			for _, v := range slice {
				if s, ok := v.(string); ok {
					strs = append(strs, s)
				} else {
					// Not a string slice, let mapstructure handle it
					return data, nil
				}
			}
			return strings.Join(strs, ","), nil
		}

		// Handle []string directly
		if slice, ok := data.([]string); ok {
			return strings.Join(slice, ","), nil
		}

		return data, nil
	}
}

// inlineMetadataHookFunc returns a DecodeHookFunc that handles the ",inline" yaml tag
// for Metadata fields in GlobAttributes and RegexSelector types.
// Since mapstructure uses TagName: "yaml" but doesn't understand the yaml ",inline" directive,
// this hook manually extracts keys that are in AllowedAttributeNames and places them in the "Metadata" field.
func inlineMetadataHookFunc() mapstructure.DecodeHookFunc {
	return func(_ reflect.Type, to reflect.Type, data any) (any, error) {
		// Only process map inputs
		inputMap, ok := data.(map[string]any)
		if !ok {
			return data, nil
		}

		// Check if target type is GlobAttributes or RegexSelector
		switch to {
		case reflect.TypeOf(services.GlobAttributes{}), reflect.TypeOf(services.RegexSelector{}):
			// continue processing
		default:
			return data, nil
		}

		// Extract fields that are in AllowedAttributeNames into metadata
		metadata := make(map[string]any)
		for k, v := range inputMap {
			if _, isAllowed := services.AllowedAttributeNames[k]; isAllowed {
				metadata[k] = v
			}
		}

		// If there are metadata fields, add them to the input map under "Metadata"
		// mapstructure will use the struct field name when the yaml tag is ",inline"
		if len(metadata) > 0 {
			// Remove metadata keys from the original map
			for k := range metadata {
				delete(inputMap, k)
			}
			// Add them under the "Metadata" key (matching the struct field name)
			inputMap["Metadata"] = metadata
		}

		return inputMap, nil
	}
}

type LogConfigOption string

const (
	LogConfigOptionYAML = LogConfigOption("yaml")
	LogConfigOptionJSON = LogConfigOption("json")
)

// Attributes configures the decoration of some extra attributes that will be
// added to each span
type Attributes struct {
	Kubernetes           transform.KubernetesDecorator `yaml:"kubernetes"`
	InstanceID           config.InstanceIDConfig       `yaml:"instance_id"`
	Select               attributes.Selection          `yaml:"select"`
	HostID               HostIDConfig                  `yaml:"host_id"`
	ExtraGroupAttributes map[string][]attr.Name        `yaml:"extra_group_attributes"`

	// RenameUnresolvedHosts will replace HostName and PeerName attributes when they are empty or contain
	// unresolved IP addresses to reduce cardinality.
	// Set this value to the empty string to disable this feature.
	RenameUnresolvedHosts         string `yaml:"rename_unresolved_hosts" env:"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS"`
	RenameUnresolvedHostsOutgoing string `yaml:"rename_unresolved_hosts_outgoing" env:"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_OUTGOING"`
	RenameUnresolvedHostsIncoming string `yaml:"rename_unresolved_hosts_incoming" env:"OTEL_EBPF_RENAME_UNRESOLVED_HOSTS_INCOMING"`

	// MetricSpanNameAggregationLimit works PER SERVICE and only relates to span_metrics.
	// When the span_name cardinality surpasses this limit, the span_name will be reported as AGGREGATED.
	// If the value <= 0, it is disabled.
	MetricSpanNameAggregationLimit int `yaml:"metric_span_names_limit" env:"OTEL_EBPF_METRIC_SPAN_NAMES_LIMIT"`
}

type HostIDConfig struct {
	// Override allows overriding the reported host.id in OBI
	Override string `yaml:"override" env:"OTEL_EBPF_HOST_ID"`
	// FetchTimeout specifies the timeout for trying to fetch the HostID from diverse Cloud Providers
	FetchTimeout time.Duration `yaml:"fetch_timeout" env:"OTEL_EBPF_HOST_ID_FETCH_TIMEOUT"`
}

type NodeJSConfig struct {
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_NODEJS_ENABLED"`
}

type JavaConfig struct {
	Enabled              bool          `yaml:"enabled" env:"OTEL_EBPF_JAVAAGENT_ENABLED"`
	Debug                bool          `yaml:"debug" env:"OTEL_EBPF_JAVAAGENT_DEBUG"`
	DebugInstrumentation bool          `yaml:"debug_instrumentation" env:"OTEL_EBPF_JAVAAGENT_DEBUG_INSTRUMENTATION"`
	Timeout              time.Duration `yaml:"attach_timeout" env:"OTEL_EBPF_JAVAAGENT_ATTACH_TIMEOUT" validate:"gte=0"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

// Validate configuration
//
//nolint:cyclop
func (c *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	// for future custom validations
	customValidations := CustomValidations{
		validationTagAgentIPIface: ValidateAgentIPIface,
	}

	if err := registerCustomValidations(validate, customValidations); err != nil {
		return ConfigError("error registering custom validations: " + err.Error())
	}

	if err := validate.Struct(c); err != nil {
		return ConfigError(err.Error())
	}

	if err := c.Discovery.Validate(); err != nil {
		return ConfigError(err.Error())
	}

	if !c.Enabled(FeatureNetO11y) && !c.Enabled(FeatureAppO11y) {
		return ConfigError("at least one of 'network' or 'application' features must be enabled. " +
			"Enable an OpenTelemetry or Prometheus metrics export, then enable any of the network* or application*" +
			"features using the 'OTEL_EBPF_METRICS_FEATURES=network,application' environment variable " +
			"or 'meter_provider: { features: [network,application] }' in the YAML configuration file. ")
	}

	if c.willUseTC() {
		if err := tcmanager.EnsureCiliumCompatibility(c.EBPF.TCBackend); err != nil {
			return ConfigError("Cilium compatibility error: " + err.Error())
		}
	}

	if c.Attributes.Kubernetes.InformersSyncTimeout == 0 {
		return ConfigError("OTEL_EBPF_KUBE_INFORMERS_SYNC_TIMEOUT duration must be greater than 0s")
	}

	if c.Enabled(FeatureNetO11y) && !c.OTELMetrics.EndpointEnabled() &&
		!c.Prometheus.EndpointEnabled() && !c.NetworkFlows.Print {
		return ConfigError("enabling network metrics requires to enable at least the OpenTelemetry" +
			" metrics exporter: otel_metrics_export or prometheus_export sections in the YAML configuration file; or the" +
			" OTEL_EXPORTER_OTLP_ENDPOINT, OTEL_EXPORTER_OTLP_METRICS_ENDPOINT or OTEL_EBPF_PROMETHEUS_PORT environment variables. For debugging" +
			" purposes, you can also set OTEL_EBPF_NETWORK_PRINT_FLOWS=true")
	}

	if !c.TracePrinter.Valid() {
		return ConfigError(fmt.Sprintf("invalid value for trace_printer: '%s'", c.TracePrinter))
	}

	if c.Enabled(FeatureAppO11y) && !c.TracePrinter.Enabled() &&
		!c.OTELMetrics.EndpointEnabled() && !c.Traces.Enabled() &&
		!c.Prometheus.EndpointEnabled() && !c.TracePrinter.Enabled() {
		return ConfigError("you need to define at least one exporter: trace_printer," +
			" otel_metrics_export, otel_traces_export or prometheus_export")
	}

	if c.Enabled(FeatureAppO11y) &&
		((c.Prometheus.EndpointEnabled() || c.OTELMetrics.EndpointEnabled()) && c.Metrics.Features.InvalidSpanMetricsConfig()) {
		return ConfigError("you can only enable one format of span metrics," +
			" application_span or application_span_otel")
	}

	if len(c.Routes.WildcardChar) > 1 {
		return ConfigError("wildcard_char can only be a single character, multiple characters are not allowed")
	}

	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && c.InternalMetrics.Prometheus.Port != 0 {
		return ConfigError("you can't enable both OTEL and Prometheus internal metrics")
	}
	if c.InternalMetrics.Exporter == imetrics.InternalMetricsExporterOTEL && !c.OTELMetrics.EndpointEnabled() {
		return ConfigError("you can't enable OTEL internal metrics without enabling OTEL metrics")
	}

	return nil
}

func (c *Config) promNetO11yEnabled() bool {
	return c.Prometheus.EndpointEnabled() && c.Metrics.Features.AnyNetwork()
}

func (c *Config) otelNetO11yEnabled() bool {
	return c.OTELMetrics.EndpointEnabled() && c.Metrics.Features.AnyNetwork()
}

func (c *Config) willUseTC() bool {
	return c.EBPF.ContextPropagation.HasIPOptions() ||
		(c.Enabled(FeatureNetO11y) && c.NetworkFlows.Source == EbpfSourceTC)
}

// Enabled checks if a given OBI feature is enabled according to the global configuration
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

func (c *Config) SpanMetricsEnabledForTraces() bool {
	return c.Metrics.Features.AnySpanMetrics() &&
		(c.OTELMetrics.EndpointEnabled() || c.Prometheus.EndpointEnabled())
}

// ExternalLogger sets the logging capabilities of OBI.
// Used for integrating OBI with an external logging system (for example Alloy)
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

	cfg.normalize()

	return &cfg, nil
}

func registerCustomValidations(validate *validator.Validate, customValidations CustomValidations) error {
	for k, v := range customValidations {
		if err := validate.RegisterValidation(k, v); err != nil {
			return fmt.Errorf("cannot add validation with the given tag %q: %w", k, err)
		}
	}
	return nil
}

// normalizeConfig normalizes user input to a common set of assumptions that are global to OBI
func (c *Config) normalize() {
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
