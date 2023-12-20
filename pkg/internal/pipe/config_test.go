package pipe

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/traces"
	"github.com/grafana/beyla/pkg/internal/transform"
)

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
channel_buffer_len: 33
ebpf:
  functions:
    - FooBar
otel_metrics_export:
  endpoint: localhost:3030
  buckets:
    duration_histogram: [0, 1, 2]
prometheus_export:
  buckets:
    request_size_histogram: [0, 10, 20, 22]
attributes:
  kubernetes:
    kubeconfig_path: /foo/bar
    enable: true
    informers_sync_timeout: 30s
  instance_id:
    dns: true
`)
	require.NoError(t, os.Setenv("BEYLA_EXECUTABLE_NAME", "tras"))
	require.NoError(t, os.Setenv("BEYLA_OPEN_PORT", "8080-8089"))
	require.NoError(t, os.Setenv("OTEL_SERVICE_NAME", "svc-name"))
	require.NoError(t, os.Setenv("BEYLA_NOOP_TRACES", "true"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:3131"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "localhost:3232"))
	require.NoError(t, os.Setenv("BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT", "3210"))
	require.NoError(t, os.Setenv("GRAFANA_CLOUD_SUBMIT", "metrics,traces"))
	require.NoError(t, os.Setenv("KUBECONFIG", "/foo/bar"))
	defer unsetEnv(t, map[string]string{
		"KUBECONFIG":      "",
		"BEYLA_OPEN_PORT": "", "BEYLA_EXECUTABLE_NAME": "", "OTEL_SERVICE_NAME": "", "BEYLA_NOOP_TRACES": "",
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

	assert.Equal(t, &Config{
		Exec:             cfg.Exec,
		Port:             cfg.Port,
		ServiceName:      "svc-name",
		ChannelBufferLen: 33,
		LogLevel:         "INFO",
		Printer:          false,
		Noop:             true,
		EBPF: ebpfcommon.TracerConfig{
			BatchLength:  100,
			BatchTimeout: time.Second,
			BpfBaseDir:   "/var/run/beyla",
		},
		Grafana: otel.GrafanaConfig{
			OTLP: otel.GrafanaOTLP{
				Submit: []string{"metrics", "traces"},
			},
		},
		Metrics: otel.MetricsConfig{
			Interval:          5 * time.Second,
			CommonEndpoint:    "localhost:3131",
			MetricsEndpoint:   "localhost:3030",
			Protocol:          otel.ProtocolUnset,
			ReportersCacheLen: 16,
			Buckets: otel.Buckets{
				DurationHistogram:    []float64{0, 1, 2},
				RequestSizeHistogram: otel.DefaultBuckets.RequestSizeHistogram,
			},
		},
		Traces: otel.TracesConfig{
			Protocol:           otel.ProtocolUnset,
			CommonEndpoint:     "localhost:3131",
			TracesEndpoint:     "localhost:3232",
			MaxQueueSize:       4096,
			MaxExportBatchSize: 4096,
			ReportersCacheLen:  16,
		},
		Prometheus: prom.PrometheusConfig{
			Path: "/metrics",
			Buckets: otel.Buckets{
				DurationHistogram:    otel.DefaultBuckets.DurationHistogram,
				RequestSizeHistogram: []float64{0, 10, 20, 22},
			}},
		InternalMetrics: imetrics.Config{
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
				KubeconfigPath:       "/foo/bar",
				Enable:               transform.EnabledTrue,
				InformersSyncTimeout: 30 * time.Second,
			},
		},
		Routes: &transform.RoutesConfig{},
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
	testCases := []map[string]string{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "localhost:1234", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_PRINT_TRACES": "true", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_PROMETHEUS_PORT": "8080", "BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			defer unsetEnv(t, tc)
			assert.NoError(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidate_error(t *testing.T) {
	testCases := []map[string]string{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "INSTRUMENT_FUNC_NAME": "bar"},
		{"BEYLA_EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "BEYLA_PRINT_TRACES": "false"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			defer unsetEnv(t, tc)
			assert.Error(t, loadConfig(t, tc).Validate())
		})
	}
}

func TestConfigValidateDiscovery(t *testing.T) {
	userConfig := bytes.NewBufferString(`print_traces: true
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
		`print_traces: true
discovery:
  services:
    - name: missing-attributes
`, `print_traces: true
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

func loadConfig(t *testing.T, env map[string]string) *Config {
	for k, v := range env {
		require.NoError(t, os.Setenv(k, v))
	}
	cfg, err := LoadConfig(nil)
	require.NoError(t, err)
	return cfg
}

func unsetEnv(t *testing.T, env map[string]string) {
	for k := range env {
		require.NoError(t, os.Unsetenv(k))
	}
}
