package pipe

import (
	"fmt"
	"io"
	"time"

	"github.com/caarlos0/env/v7"
	"gopkg.in/yaml.v3"

	"github.com/grafana/ebpf-autoinstrument/pkg/ebpf/nethttp"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/debug"
	"github.com/grafana/ebpf-autoinstrument/pkg/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

var defaultConfig = Config{
	ChannelBufferLen: 10,
	LogLevel:         "INFO",
	EBPF: nethttp.EBPFTracer{
		Functions: []string{
			"net/http.HandlerFunc.ServeHTTP",
			"github.com/gin-gonic/gin.(*Engine).ServeHTTP",
		},
		GRPCHandleStream: []string{"google.golang.org/grpc.(*Server).handleStream"},
		GRPCWriteStatus:  []string{"google.golang.org/grpc/internal/transport.(*http2Server).WriteStatus"},
		RuntimeNewproc1:  []string{"runtime.newproc1"},
		RuntimeGoexit1:   []string{"runtime.goexit1"},
	},
	Metrics: otel.MetricsConfig{
		Interval: 5 * time.Second,
	},
	Printer: true, // TODO: false
	Noop:    false,
}

// TODO: support all the OTEL_ stuff here: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md
type Config struct {
	EBPF nethttp.EBPFTracer `nodeId:"ebpf" sendTo:"routes" yaml:"ebpf"`

	// Routes is an optional node. If not set, data will be directly forwarded to exporters.
	Routes *transform.RoutesConfig `nodeId:"routes" forwardTo:"otel_metrics,otel_traces,print,noop" yaml:"routes"`

	Metrics otel.MetricsConfig `nodeId:"otel_metrics" yaml:"otel_metrics_export"`
	Traces  otel.TracesConfig  `nodeId:"otel_traces" yaml:"otel_traces_export"`
	Printer debug.PrintEnabled `nodeId:"print" yaml:"print" env:"PRINT_TRACES"`
	Noop    debug.NoopEnabled  `nodeId:"noop" yaml:"noop" env:"NOOP_TRACES"`

	ChannelBufferLen int    `yaml:"channel_buffer_len" env:"CHANNEL_BUFFER_LEN" nodeId:"-"`
	LogLevel         string `yaml:"log_level" env:"LOG_LEVEL" nodeId:"-"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

func (c *Config) Validate() error {
	if c.EBPF.Exec == "" {
		return ConfigError("missing EXECUTABLE_NAME property")
	}
	if len(c.EBPF.Functions) == 0 {
		return ConfigError("missing INSTRUMENT_FUNCTIONS property")
	}
	if !c.Noop.Enabled() && !c.Printer.Enabled() &&
		!c.Metrics.Enabled() && !c.Traces.Enabled() {
		return ConfigError("at least one of the following properties must be set: " +
			"NOOP_TRACES, PRINT_TRACES, OTEL_EXPORTER_OTLP_ENDPOINT, " +
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	return nil
}

// LoadConfig overrides configuration in the following order (from less to most priority)
// 1 - Default configuration (default_config.yml)
// 2 - Contents of the provided file reader (nillable)
// 3 - Environment variables
func LoadConfig(file io.Reader) (*Config, error) {
	cfg := defaultConfig
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
	return &cfg, nil
}
