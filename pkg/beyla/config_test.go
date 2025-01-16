package beyla

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/config"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/debug"
	"github.com/grafana/beyla/pkg/export/instrumentations"
	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/export/prom"
	"github.com/grafana/beyla/pkg/internal/ebpf/tcmanager"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/netolly/transform/cidr"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/kubeflags"
	"github.com/grafana/beyla/pkg/services"
	"github.com/grafana/beyla/pkg/transform"
)

type envMap map[string]string

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
trace_printer: json
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
attributes:
  kubernetes:
    kubeconfig_path: /foo/bar
    enable: true
    informers_sync_timeout: 30s
    meta_naming_sources:
      annotations:
        service_namespace: ["huha.com/yeah"]
      labels:
        service_name: ["titi.com/lala"]
  instance_id:
    dns: true
  host_id:
    override: the-host-id
    fetch_timeout: 4s
  select:
    beyla.network.flow:
      include: ["foo", "bar"]
      exclude: ["baz", "bae"]
network:
  enable: true
  cidrs:
    - 10.244.0.0/16
`)
	require.NoError(t, os.Setenv("BEYLA_EXECUTABLE_NAME", "tras"))
	require.NoError(t, os.Setenv("BEYLA_NETWORK_AGENT_IP", "1.2.3.4"))
	require.NoError(t, os.Setenv("BEYLA_OPEN_PORT", "8080-8089"))
	require.NoError(t, os.Setenv("OTEL_SERVICE_NAME", "svc-name"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:3131"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "localhost:3232"))
	require.NoError(t, os.Setenv("BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT", "3210"))
	require.NoError(t, os.Setenv("GRAFANA_CLOUD_SUBMIT", "metrics,traces"))
	require.NoError(t, os.Setenv("KUBECONFIG", "/foo/bar"))
	require.NoError(t, os.Setenv("BEYLA_NAME_RESOLVER_SOURCES", "k8s,dns"))
	defer unsetEnv(t, envMap{
		"KUBECONFIG":      "",
		"BEYLA_OPEN_PORT": "", "BEYLA_EXECUTABLE_NAME": "", "OTEL_SERVICE_NAME": "",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "", "GRAFANA_CLOUD_SUBMIT": "",
	})

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

	nc := defaultNetworkConfig
	nc.Enable = true
	nc.AgentIP = "1.2.3.4"
	nc.CIDRs = cidr.Definitions{"10.244.0.0/16"}

	metaSources := kube.DefaultMetadataSources
	metaSources.Annotations.ServiceNamespace = []string{"huha.com/yeah"}
	metaSources.Labels.ServiceName = []string{"titi.com/lala"}

	assert.Equal(t, &Config{
		Exec:             cfg.Exec,
		Port:             cfg.Port,
		ServiceName:      "svc-name",
		ChannelBufferLen: 33,
		LogLevel:         "INFO",
		EnforceSysCaps:   false,
		Printer:          false,
		TracePrinter:     "json",
		EBPF: config.EBPFTracer{
			BatchLength:        100,
			BatchTimeout:       time.Second,
			HTTPRequestTimeout: 30 * time.Second,
			TCBackend:          tcmanager.TCBackendAuto,
		},
		Grafana: otel.GrafanaConfig{
			OTLP: otel.GrafanaOTLP{
				Submit: []string{"metrics", "traces"},
			},
		},
		NetworkFlows: nc,
		Metrics: otel.MetricsConfig{
			OTELIntervalMS:    60_000,
			CommonEndpoint:    "localhost:3131",
			MetricsEndpoint:   "localhost:3030",
			Protocol:          otel.ProtocolUnset,
			ReportersCacheLen: ReporterLRUSize,
			Buckets: otel.Buckets{
				DurationHistogram:    []float64{0, 1, 2},
				RequestSizeHistogram: otel.DefaultBuckets.RequestSizeHistogram,
			},
			Features: []string{"application"},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			HistogramAggregation: "base2_exponential_bucket_histogram",
			TTL:                  defaultMetricsTTL,
		},
		Traces: otel.TracesConfig{
			Protocol:           otel.ProtocolUnset,
			CommonEndpoint:     "localhost:3131",
			TracesEndpoint:     "localhost:3232",
			MaxQueueSize:       4096,
			MaxExportBatchSize: 4096,
			ReportersCacheLen:  ReporterLRUSize,
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
		},
		Prometheus: prom.PrometheusConfig{
			Path:     "/metrics",
			Features: []string{otel.FeatureApplication},
			Instrumentations: []string{
				instrumentations.InstrumentationALL,
			},
			TTL:                         time.Second,
			SpanMetricsServiceCacheSize: 10000,
			Buckets: otel.Buckets{
				DurationHistogram:    otel.DefaultBuckets.DurationHistogram,
				RequestSizeHistogram: []float64{0, 10, 20, 22},
			}},
		InternalMetrics: imetrics.Config{
			Exporter: imetrics.InternalMetricsExporterDisabled,
			Prometheus: imetrics.PrometheusConfig{
				Port: 3210,
				Path: "/internal/metrics",
			},
		},
		Attributes: Attributes{
			InstanceID: traces.InstanceIDConfig{
				HostnameDNSResolution: true,
			},
			Kubernetes: transform.KubernetesDecorator{
				KubeconfigPath:        "/foo/bar",
				Enable:                kubeflags.EnabledTrue,
				InformersSyncTimeout:  30 * time.Second,
				InformersResyncPeriod: 30 * time.Minute,
				MetadataSources:       metaSources,
			},
			HostID: HostIDConfig{
				Override:     "the-host-id",
				FetchTimeout: 4 * time.Second,
			},
			Select: attributes.Selection{
				attributes.BeylaNetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"foo", "bar"},
					Exclude: []string{"baz", "bae"},
				},
			},
		},
		Routes: &transform.RoutesConfig{
			Unmatch:      transform.UnmatchHeuristic,
			WildcardChar: "*",
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
		Discovery: services.DiscoveryConfig{
			ExcludeOTelInstrumentedServices: true,
			ExcludeSystemServices:           `.*alloy.*|.*otelcol.*|.*beyla.*`,
		},
	}, cfg)
}

func TestConfig_ServiceName(t *testing.T) {
	// ServiceName property can be handled via two different env vars BEYLA_SERVICE_NAME and OTEL_SERVICE_NAME (for
	// compatibility with OpenTelemetry)
	require.NoError(t, os.Setenv("BEYLA_SERVICE_NAME", "some-svc-name"))
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.Equal(t, "some-svc-name", cfg.ServiceName)
}

func TestConfigValidate(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_PRINT_TRACES": "true", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "disabled", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_PRINT_TRACES": "false", "BEYLA_TRACE_PRINTER": "text", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "text", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "json", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "json_indent", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_TRACE_PRINTER": "counter", "BEYLA_EXECUTABLE_NAME": "foo"},
		{"BEYLA_PROMETHEUS_PORT": "8080", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_INTERNAL_OTEL_METRICS": "true", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			defer unsetEnv(t, tc)
			assert.NoError(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidate_error(t *testing.T) {
	testCases := []envMap{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "BEYLA_PRINT_TRACES": "false"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "text"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "json"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "json_indent"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_PRINT_TRACES": "true", "BEYLA_TRACE_PRINTER": "counter"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			defer unsetEnv(t, tc)
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
			env:      envMap{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_TRACE_PRINTER": "json", "BEYLA_PRINT_TRACES": "true"},
			errorMsg: "print_traces and trace_printer are mutually exclusive, use trace_printer instead",
		},
		{
			env:      envMap{"BEYLA_EXECUTABLE_NAME": "foo"},
			errorMsg: "you need to define at least one exporter: trace_printer, grafana, otel_metrics_export, otel_traces_export or prometheus_export",
		},
	}

	for i := range testCases {
		cfg := loadConfig(t, testCases[i].env)
		unsetEnv(t, testCases[i].env)

		err := cfg.Validate()
		require.Error(t, err)
		assert.Equal(t, err.Error(), testCases[i].errorMsg)
	}
}

func TestConfigValidate_TracePrinterFallback(t *testing.T) {
	env := envMap{"BEYLA_EXECUTABLE_NAME": "foo", "BEYLA_PRINT_TRACES": "true"}

	cfg := loadConfig(t, env)

	unsetEnv(t, env)

	err := cfg.Validate()
	require.NoError(t, err)
	assert.True(t, cfg.Printer.Enabled())
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
	// OTEL_GO_AUTO_TARGET_EXE is an alias to BEYLA_EXECUTABLE_NAME
	// (Compatibility with OpenTelemetry)
	require.NoError(t, os.Setenv("OTEL_GO_AUTO_TARGET_EXE", "testserver"))
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Exec.IsSet()) // Exec maps to BEYLA_EXECUTABLE_NAME
}

func TestConfig_NetworkImplicit(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to BEYLA_EXECUTABLE_NAME
	// (Compatibility with OpenTelemetry)
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318"))
	require.NoError(t, os.Setenv("BEYLA_OTEL_METRIC_FEATURES", "network"))
	cfg, err := LoadConfig(bytes.NewReader(nil))
	require.NoError(t, err)
	assert.True(t, cfg.Enabled(FeatureNetO11y)) // Net o11y should be on
}

func TestConfig_NetworkImplicitProm(t *testing.T) {
	// OTEL_GO_AUTO_TARGET_EXE is an alias to BEYLA_EXECUTABLE_NAME
	// (Compatibility with OpenTelemetry)
	require.NoError(t, os.Setenv("BEYLA_PROMETHEUS_PORT", "9090"))
	require.NoError(t, os.Setenv("BEYLA_PROMETHEUS_FEATURES", "network"))
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
		tracing       bool
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
		tracing: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         config.EBPFTracer{BpfDebug: true},
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
		tracing: true,
		expectedCfg: Config{
			TracePrinter: debug.TracePrinterText,
			EBPF:         config.EBPFTracer{BpfDebug: true},
			NetworkFlows: NetworkConfig{Enable: true, Print: true},
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{NetworkFlows: NetworkConfig{Enable: tc.networkEnable}}
			out := &bytes.Buffer{}
			cfg.ExternalLogger(tc.handler(out), tc.tracing)
			slog.Info("information", "arg", "info")
			slog.Debug("debug", "arg", "debug")
			assert.Regexp(t, tc.expectedText, strings.TrimSpace(out.String()))
			assert.Equal(t, tc.expectedCfg, cfg)
		})
	}
}

func loadConfig(t *testing.T, env envMap) *Config {
	for k, v := range env {
		require.NoError(t, os.Setenv(k, v))
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	return cfg
}

func unsetEnv(t *testing.T, env envMap) {
	for k := range env {
		require.NoError(t, os.Unsetenv(k))
	}
}
