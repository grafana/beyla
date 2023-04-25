package pipe

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
)

func TestConfig_Overrides(t *testing.T) {
	userConfig := bytes.NewBufferString(`
channel_buffer_len: 33
ebpf:
  executable_name: tras
  functions:
    - FooBar
otel_metrics_export:
  endpoint: localhost:3030
`)
	require.NoError(t, os.Setenv("OTEL_SERVICE_NAME", "svc-name"))
	require.NoError(t, os.Setenv("NOOP_TRACES", "true"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:3131"))
	require.NoError(t, os.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "localhost:3232"))
	defer unsetEnv(t, map[string]string{
		"OTEL_SERVICE_NAME": "", "NOOP_TRACES": "",
		"OTEL_EXPORTER_OTLP_ENDPOINT": "", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "",
	})

	cfg, err := LoadConfig(userConfig)
	require.NoError(t, err)
	assert.NoError(t, cfg.Validate())

	assert.Equal(t, &Config{
		ChannelBufferLen: 33,
		LogLevel:         "INFO",
		Printer:          false,
		Noop:             true,
		EBPF: nethttp.EBPFTracer{
			Exec:                    "tras",
			Functions:               []string{"FooBar"},
			HTTPStartBackgroundRead: []string{"net/http.(*connReader).startBackgroundRead"},
			GRPCWriteStatus:         []string{"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus"},
			GRPCHandleStream:        []string{"google.golang.org/grpc.(*Server).handleStream"},
			RuntimeNewproc1:         []string{"runtime.newproc1"},
			RuntimeGoexit1:          []string{"runtime.goexit1"},
			BatchLength:             100,
			BatchTimeout:            time.Second,
		},
		Metrics: otel.MetricsConfig{
			ServiceName: "svc-name",
			Interval:    5 * time.Second,
			Endpoint:    "localhost:3131",
		},
		Traces: otel.TracesConfig{
			ServiceName:        "svc-name",
			Endpoint:           "localhost:3131",
			TracesEndpoint:     "localhost:3232",
			MaxQueueSize:       4096,
			MaxExportBatchSize: 4096,
		},
	}, cfg)
}

func TestConfigValidate(t *testing.T) {
	testCases := []map[string]string{
		{"OTEL_EXPORTER_OTLP_ENDPOINT": "localhost:1234", "EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "localhost:1234", "EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "localhost:1234", "EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
		{"PRINT_TRACES": "true", "EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar"},
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
		{"EXECUTABLE_NAME": "foo", "INSTRUMENT_FUNC_NAME": "bar", "PRINT_TRACES": "false"},
	}
	for n, tc := range testCases {
		t.Run(fmt.Sprint("case", n), func(t *testing.T) {
			defer unsetEnv(t, tc)
			assert.Error(t, loadConfig(t, tc).Validate())
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
