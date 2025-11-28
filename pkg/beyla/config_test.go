package beyla

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	obiconfig "go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/debug"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
	"go.opentelemetry.io/obi/pkg/netolly/cidr"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/transform"

	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
	servicesextra "github.com/grafana/beyla/v2/pkg/services"
)

type envMap map[string]string

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
trace_printer: json
shutdown_timeout: 30s
channel_buffer_len: 33
ebpf:
  functions:
    - FooBar
otel_metrics_export:
  ttl: 5m
  endpoint: localhost:3030
  buckets:
    duration_histogram: [0, 1, 2]
  histogram_aggregation: base2_exponential_bucket_histogram
prometheus_export:
  ttl: 1s
  buckets:
    request_size_histogram: [0, 10, 20, 22]
    response_size_histogram: [0, 10, 20, 22]
attributes:
  kubernetes:
    kubeconfig_path: /foo/bar
    enable: true
    informers_sync_timeout: 30s
    resource_labels:
      service.namespace: ["huha.com/yeah"]
  instance_id:
    dns: true
  host_id:
    override: the-host-id
    fetch_timeout: 4s
  select:
    beyla.network.flow:
      include: ["foo", "bar"]
      exclude: ["baz", "bae"]
  extra_group_attributes:
    k8s_app_meta: ["k8s.app.version"]
discovery:
  services:                                                                                                                                                                                                      
    - k8s_namespace: .  
  instrument:
    - k8s_pod_name: "*"
network:
  enable: true
  cidrs:
    - 10.244.0.0/16
`)
	t.Setenv("BEYLA_EXECUTABLE_NAME", "tras")
	t.Setenv("BEYLA_NETWORK_AGENT_IP", "1.2.3.4")
	t.Setenv("BEYLA_OPEN_PORT", "8080-8089")
	t.Setenv("OTEL_SERVICE_NAME", "svc-name")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:3131")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "localhost:3232")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_PROTOCOL", "http/protobuf")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "http/protobuf")
	t.Setenv("BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT", "3210")
	t.Setenv("GRAFANA_CLOUD_SUBMIT", "metrics,traces")
	t.Setenv("KUBECONFIG", "/foo/bar")
	t.Setenv("BEYLA_NAME_RESOLVER_SOURCES", "k8s,dns")
	defer unsetOBIEnv(t)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate())

	// first test executable, as we can't test equality on it
	assert.True(t, cfg.Exec.MatchString("atrassss"))
	assert.False(t, cfg.Exec.MatchString("foobar"))

	// test also openports by the same reason
	assert.True(t, cfg.Port.Matches(8088))
	assert.False(t, cfg.Port.Matches(8078))
	assert.False(t, cfg.Port.Matches(8098))

	nc := obi.DefaultNetworkConfig
	nc.Enable = true
	nc.AgentIP = "1.2.3.4"
	nc.CIDRs = cidr.Definitions{"10.244.0.0/16"}

	nsNamespaceAttr := services.NewRegexp(".")
	nsPodNameAttr := services.NewGlob("*")

	metaSources := maps.Clone(kube.DefaultResourceLabels)
	metaSources["service.namespace"] = []string{"huha.com/yeah"}
	// uncache internal field
	cfg.obi = nil
	assert.Equal(t, &Config{
		Exec:             cfg.Exec,
		Port:             cfg.Port,
		ServiceName:      "svc-name",
		ChannelBufferLen: 33,
		LogLevel:         "INFO",
		ShutdownTimeout:  30 * time.Second,
		EnforceSysCaps:   false,
		TracePrinter:     "json",
		EBPF: obiconfig.EBPFTracer{
			BatchLength:               100,
			BatchTimeout:              time.Second,
			HTTPRequestTimeout:        0,
			TCBackend:                 obiconfig.TCBackendAuto,
			ContextPropagationEnabled: false,
			ContextPropagation:        obiconfig.ContextPropagationDisabled,
			RedisDBCache: obiconfig.RedisDBCacheConfig{
				Enabled: false,
				MaxSize: 1000,
			},
			BufferSizes: obiconfig.EBPFBufferSizes{
				HTTP:     0,
				MySQL:    0,
				Postgres: 0,
			},
			MySQLPreparedStatementsCacheSize:    1024,
			MongoRequestsCacheSize:              1024,
			PostgresPreparedStatementsCacheSize: 1024,
			KafkaTopicUUIDCacheSize:             1024,
			MaxTransactionTime:                  5 * time.Minute,
			DNSRequestTimeout:                   5 * time.Second,
		},
		Grafana: otel.GrafanaConfig{
			OTLP: otel.GrafanaOTLP{
				Submit: []string{"metrics", "traces"},
			},
		},
		NetworkFlows: nc,
		Metrics: otelcfg.MetricsConfig{
			OTELIntervalMS:    60_000,
			CommonEndpoint:    "localhost:3131",
			MetricsEndpoint:   "localhost:3030",
			MetricsProtocol:   otelcfg.ProtocolHTTPProtobuf,
			ReportersCacheLen: ReporterLRUSize,
			Buckets: otelcfg.Buckets{
				DurationHistogram:     []float64{0, 1, 2},
				RequestSizeHistogram:  otelcfg.DefaultBuckets.RequestSizeHistogram,
				ResponseSizeHistogram: otelcfg.DefaultBuckets.ResponseSizeHistogram,
			},
			Features: []string{"application"},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			HistogramAggregation: "base2_exponential_bucket_histogram",
			TTL:                  5 * time.Minute,
		},
		Traces: otelcfg.TracesConfig{
			TracesProtocol:    otelcfg.ProtocolHTTPProtobuf,
			CommonEndpoint:    "localhost:3131",
			TracesEndpoint:    "localhost:3232",
			MaxQueueSize:      4096,
			BatchTimeout:      15 * time.Second,
			ReportersCacheLen: ReporterLRUSize,
			Instrumentations: []string{
				instrumentations.InstrumentationHTTP,
				instrumentations.InstrumentationGRPC,
				instrumentations.InstrumentationSQL,
				instrumentations.InstrumentationRedis,
				instrumentations.InstrumentationKafka,
				instrumentations.InstrumentationMongo,
			},
		},
		Prometheus: prom.PrometheusConfig{
			Path:     "/metrics",
			Features: []string{otelcfg.FeatureApplication},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			TTL:                         time.Second,
			SpanMetricsServiceCacheSize: 10000,
			Buckets: otelcfg.Buckets{
				DurationHistogram:     otelcfg.DefaultBuckets.DurationHistogram,
				RequestSizeHistogram:  []float64{0, 10, 20, 22},
				ResponseSizeHistogram: []float64{0, 10, 20, 22},
			},
		},
		InternalMetrics: imetrics.Config{
			Exporter: imetrics.InternalMetricsExporterDisabled,
			Prometheus: imetrics.PrometheusConfig{
				Port: 3210,
				Path: "/internal/metrics",
			},
			BpfMetricScrapeInterval: 15 * time.Second,
		},
		Attributes: Attributes{
			InstanceID: obiconfig.InstanceIDConfig{
				HostnameDNSResolution: true,
			},
			Kubernetes: transform.KubernetesDecorator{
				KubeconfigPath:        "/foo/bar",
				Enable:                kubeflags.EnabledTrue,
				InformersSyncTimeout:  30 * time.Second,
				InformersResyncPeriod: 30 * time.Minute,
				ResourceLabels:        metaSources,
			},
			HostID: HostIDConfig{
				Override:     "the-host-id",
				FetchTimeout: 4 * time.Second,
			},
			Select: attributes.Selection{
				attributes.NetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"foo", "bar"},
					Exclude: []string{"baz", "bae"},
				},
			},
			ExtraGroupAttributes: map[string][]attr.Name{
				"k8s_app_meta": {"k8s.app.version"},
			},
			RenameUnresolvedHosts:          "unresolved",
			RenameUnresolvedHostsOutgoing:  "outgoing",
			RenameUnresolvedHostsIncoming:  "incoming",
			MetricSpanNameAggregationLimit: 100,
		},
		Routes: &transform.RoutesConfig{
			Unmatch:                   transform.UnmatchHeuristic,
			WildcardChar:              "*",
			MaxPathSegmentCardinality: 10,
		},
		NameResolver: &transform.NameResolverConfig{
			Sources:  []string{"k8s", "dns"},
			CacheLen: 1024,
			CacheTTL: 5 * time.Minute,
		},
		Processes: process.CollectConfig{
			RunMode:  process.RunModePrivileged,
			Interval: 5 * time.Second,
		},
		Discovery: servicesextra.BeylaDiscoveryConfig{
			ExcludeOTelInstrumentedServices: true,
			MinProcessAge:                   5 * time.Second,
			Services: services.RegexDefinitionCriteria{{Metadata: map[string]*services.RegexpAttr{
				"k8s_namespace": &nsNamespaceAttr,
			}}},
			Instrument: services.GlobDefinitionCriteria{{Metadata: map[string]*services.GlobAttr{
				"k8s_pod_name": &nsPodNameAttr,
			}}},
			DefaultExcludeServices: services.RegexDefinitionCriteria{
				services.RegexSelector{
					Path: services.NewRegexp("(?:^|/)(beyla$|alloy$|prometheus-config-reloader$|otelcol[^/]*$)"),
				},
				services.RegexSelector{
					Metadata: map[string]*services.RegexpAttr{"k8s_namespace": &servicesextra.K8sDefaultNamespacesRegex},
				},
			},
			DefaultExcludeInstrument: services.GlobDefinitionCriteria{
				services.GlobAttributes{
					Path: services.NewGlob("{*beyla,*alloy,*prometheus-config-reloader,*ebpf-instrument,*otelcol,*otelcol-contrib,*otelcol-contrib[!/]*}"),
				},
				services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{"k8s_namespace": &servicesextra.K8sDefaultNamespacesGlob},
				},
				services.GlobAttributes{
					Metadata: map[string]*services.GlobAttr{"k8s_container_name": &servicesextra.K8sDefaultExcludeContainerNamesGlob},
				},
			},
			DefaultOtlpGRPCPort:   4317,
			RouteHarvesterTimeout: 10 * time.Second,
			RouteHarvestConfig: servicesextra.RouteHarvestingConfig{
				JavaHarvestDelay: 60 * time.Second,
			},
		},
		NodeJS: obi.NodeJSConfig{Enabled: true},
	}, cfg)
}

func TestConfig_ServiceName(t *testing.T) {
	// ServiceName property can be handled via two different env vars BEYLA_SERVICE_NAME and OTEL_SERVICE_NAME (for
	// compatibility with OpenTelemetry)
	t.Setenv("BEYLA_SERVICE_NAME", "some-svc-name")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, "some-svc-name", cfg.ServiceName)
}

func TestConfig_ShutdownTimeout(t *testing.T) {
	t.Setenv("BEYLA_SHUTDOWN_TIMEOUT", "1m")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, time.Minute, cfg.ShutdownTimeout)
}

func TestConfigValidate(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_TRACE_PRINTER": "text", "BEYLA_SHUTDOWN_TIMEOUT": "1m", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "json", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "json_indent", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "counter", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_PROMETHEUS_PORT": "8080", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_INTERNAL_OTEL_METRICS": "true", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			assert.NoError(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidate_error(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "BEYLA_TRACE_PRINTER": "disabled"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "BEYLA_TRACE_PRINTER": ""},
		{"BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "BEYLA_TRACE_PRINTER": "invalid"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			assert.Error(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidateDiscovery(t *testing.T) {
	userConfig := bytes.NewBufferString(`trace_printer: text
discovery:
  services:
    - name: foo
      k8s_pod_name: tralara
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateDiscovery_Errors(t *testing.T) {
	for _, tc := range []string{
		`trace_printer: text
discovery:
  services:
    - name: missing-attributes
`, `trace_printer: text
discovery:
  services:
    - name: invalid-attribute
      k8s_unexisting_stuff: lalala
`,
	} {
		testCaseName := regexp.MustCompile("name: (.+)\n").FindStringSubmatch(tc)[1]
		t.Run(testCaseName, func(t *testing.T) {
			userConfig := bytes.NewBufferString(tc)
			cfg, err := LoadConfig(userConfig)
			require.NoError(t, err)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestConfigValidate_Network_Kube(t *testing.T) {
	userConfig := bytes.NewBufferString(`
otel_metrics_export:
  endpoint: http://otelcol:4318
attributes:
  kubernetes:
    enable: true
  select:
    beyla_network_flow_bytes:
      include:
        - k8s.src.name
        - k8s.dst.name
network:
  enable: true
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidate_TracePrinter(t *testing.T) {
	type test struct {
		env      envMap
		errorMsg string
	}

	testCases := []test{
		{
			env:      envMap{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_TRACE_PRINTER": "invalid_printer"},
			errorMsg: "invalid value for trace_printer: 'invalid_printer'",
		},
		{
			env:      envMap{"BEYLA_EXECUTABLE_NAME": "foo"},
			errorMsg: "you need to define at least one exporter: trace_printer, grafana, otel_metrics_export, otel_traces_export or prometheus_export",
		},
	}

	for i := range testCases {
		t.Run(fmt.Sprint("case", i), func(t *testing.T) {
			cfg := loadConfig(t, testCases[i].env)

			err := cfg.Validate()
			require.Error(t, err)
			assert.Equal(t, err.Error(), testCases[i].errorMsg)
		})
	}
}

func TestConfigValidate_TracePrinterFallback(t *testing.T) {
	env := envMap{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_TRACE_PRINTER": "text"}

	cfg := loadConfig(t, env)

	err := cfg.Validate()
	require.NoError(t, err)
	assert.Equal(t, cfg.TracePrinter, debug.TracePrinterText)
}

func TestConfigValidateRoutes(t *testing.T) {
	userConfig := bytes.NewBufferString(`executable_name: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "*"
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
}

func TestConfigValidateRoutes_Errors(t *testing.T) {
	for _, tc := range []string{
		`executable_name: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "##"
`, `executable_name: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "random"
`,
	} {
		testCaseName := regexp.MustCompile("wildcard_char: (.+)\n").FindStringSubmatch(tc)[1]
		t.Run(testCaseName, func(t *testing.T) {
			userConfig := bytes.NewBufferString(tc)
			cfg, err := LoadConfig(userConfig)
			require.NoError(t, err)
			require.Error(t, cfg.Validate())
		})
	}
}

func TestConfig_OtelGoAutoEnv(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to OTEL_EBPF_AUTO_TARGET_EXE
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_GO_AUTO_TARGET_EXE", "*testserver")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.AutoTargetExe.MatchString("/bin/testserver"))
	assert.False(t, cfg.AutoTargetExe.MatchString("somethingelse"))
}

func TestConfig_NetworkImplicit(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to BEYLA_EXECUTABLE_NAME
	// (Compatibility with OpenTelemetry)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("BEYLA_OTEL_METRIC_FEATURES", "network")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
}

func TestConfig_NetworkImplicitProm(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to BEYLA_EXECUTABLE_NAME
	// (Compatibility with OpenTelemetry)
	t.Setenv("BEYLA_PROMETHEUS_PORT", "9090")
	t.Setenv("BEYLA_PROMETHEUS_FEATURES", "network")
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
}

func TestConfig_ExternalLogger(t *testing.T) {
	type testCase struct {
		name          string
		handler       func(out io.Writer) slog.Handler
		expectedText  *regexp.Regexp
		expectedCfg   Config
		debugMode     bool
		networkEnable bool
	}
	for _, tc := range []testCase{{
		name: "default info log",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelInfo})
		},
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info$`),
	}, {
		name: "default debug log",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info
time=\S+ level=DEBUG msg=debug arg=debug$`),
		debugMode: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         obiconfig.EBPFTracer{BpfDebug: true, ProtocolDebug: true},
		},
	}, {
		name: "debug log with network flows",
		handler: func(out io.Writer) slog.Handler {
			return slog.NewTextHandler(out, &slog.HandlerOptions{Level: slog.LevelDebug})
		},
		networkEnable: true,
		expectedText: regexp.MustCompile(
			`^time=\S+ level=INFO msg=information arg=info
time=\S+ level=DEBUG msg=debug arg=debug$`),
		debugMode: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         obiconfig.EBPFTracer{BpfDebug: true, ProtocolDebug: true},
			NetworkFlows: obi.NetworkConfig{Enable: true, Print: true},
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{NetworkFlows: obi.NetworkConfig{Enable: tc.networkEnable}}
			out := &bytes.Buffer{}
			cfg.ExternalLogger(tc.handler(out), tc.debugMode)
			slog.Info("information", "arg", "info")
			slog.Debug("debug", "arg", "debug")
			assert.Regexp(t, tc.expectedText, strings.TrimSpace(out.String()))
			assert.Equal(t, tc.expectedCfg, cfg)
		})
	}
}

func TestDefaultExclusionFilter(t *testing.T) {
	c := DefaultConfig().Discovery.DefaultExcludeServices

	assert.True(t, c[0].Path.MatchString("beyla"))
	assert.True(t, c[0].Path.MatchString("alloy"))
	assert.True(t, c[0].Path.MatchString("prometheus-config-reloader"))
	assert.True(t, c[0].Path.MatchString("otelcol-contrib"))

	assert.False(t, c[0].Path.MatchString("/usr/bin/beyla/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/alloy/test"))
	assert.False(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib/test"))

	assert.True(t, c[0].Path.MatchString("/beyla"))
	assert.True(t, c[0].Path.MatchString("/alloy"))
	assert.True(t, c[0].Path.MatchString("/bin/prometheus-config-reloader"))
	assert.True(t, c[0].Path.MatchString("/otelcol-contrib"))

	assert.True(t, c[0].Path.MatchString("/usr/bin/beyla"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/alloy"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib"))
	assert.True(t, c[0].Path.MatchString("/usr/bin/otelcol-contrib123"))
}

func TestWillUseTC(t *testing.T) {
	env := envMap{"BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION": "true"}
	cfg := loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION": "false"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_CONTEXT_PROPAGATION": "disabled"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_CONTEXT_PROPAGATION": "all"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_CONTEXT_PROPAGATION": "headers"}
	cfg = loadConfig(t, env)
	assert.False(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_CONTEXT_PROPAGATION": "ip"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())

	env = envMap{"BEYLA_BPF_CONTEXT_PROPAGATION": "disabled", "BEYLA_NETWORK_SOURCE": "tc", "BEYLA_NETWORK_METRICS": "true"}
	cfg = loadConfig(t, env)
	assert.True(t, cfg.willUseTC())
}

func TestOBIConfigConversion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Prometheus.Port = 6060
	cfg.Metrics.MetricsEndpoint = "http://localhost:4318"
	cfg.Discovery = servicesextra.BeylaDiscoveryConfig{
		Instrument: services.GlobDefinitionCriteria{
			{Path: services.NewGlob("hello*")},
			{Path: services.NewGlob("bye*")},
		},
	}

	// TODO: add more fields that you want to verify they are properly converted
	dst := cfg.AsOBI()
	assert.Equal(t, dst.Prometheus.Port, 6060)
	assert.Equal(t, dst.Metrics.MetricsEndpoint, "http://localhost:4318")
	assert.Equal(t,
		services.GlobDefinitionCriteria{
			{Path: services.NewGlob("hello*")},
			{Path: services.NewGlob("bye*")},
		},
		dst.Discovery.Instrument)
}

func TestConfigSurveyOverridesExcludeDefaults(t *testing.T) {
	userConfig := bytes.NewBufferString(`executable_name: foo
trace_printer: text
routes:
  unmatched: heuristic
  wildcard_char: "*"
discovery:
  services:
    - exe_path: python
      containers_only: true
  survey:
    - exe_path: .
      containers_only: true
`)
	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	assert.Equal(t, servicesextra.DefaultExcludeServicesWithSurvey, cfg.Discovery.DefaultExcludeServices)
	assert.Equal(t, servicesextra.DefaultExcludeInstrumentWithSurvey, cfg.Discovery.DefaultExcludeInstrument)
}

func loadConfig(t *testing.T, env envMap) *Config {
	for k, v := range env {
		t.Setenv(k, v)
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	unsetOBIEnv(t)
	return cfg
}

func unsetOBIEnv(t *testing.T) {
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "OTEL_EBPF_") {
			require.NoError(t, os.Unsetenv(env[:strings.IndexByte(env, '=')]))
		}
	}
}
