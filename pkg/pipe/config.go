package pipe

import "time"

// TODO: support all the OTEL_ stuff here: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md
type Config struct {
	Exec                string        `env:"EXECUTABLE_NAME"`
	FuncName            string        `env:"INSTRUMENT_FUNC_NAME" envDefault:"net/http.HandlerFunc.ServeHTTP"`
	MetricsInterval     time.Duration `env:"METRICS_INTERVAL" envDefault:"5s"`
	NoopTracer          bool          `env:"NOOP_TRACES" envDefault:"false"` // TODO: false
	OTELEndpoint        string        `env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OTELMetricsEndpoint string        `env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
	OTELTracesEndpoint  string        `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`
	PrintTraces         bool          `env:"PRINT_TRACES" envDefault:"true"` // TODO: false
	ChannelBufferLen    int           `env:"CHANNEL_BUFFER_LEN" envDefault:"10"`
}

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

func (c *Config) Validate() error {
	if c.Exec == "" {
		return ConfigError("missing EXECUTABLE_NAME property")
	}
	if c.FuncName == "" {
		return ConfigError("missing INSTRUMENT_FUNC_NAME property")
	}
	if !c.NoopTracer && !c.PrintTraces && c.OTELEndpoint == "" &&
		c.OTELTracesEndpoint == "" && c.OTELMetricsEndpoint == "" {
		return ConfigError("at least one of the following properties must be set: " +
			"NOOP_TRACES, PRINT_TRACES, OTEL_EXPORTER_OTLP_ENDPOINT, " +
			"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
	}
	return nil
}
