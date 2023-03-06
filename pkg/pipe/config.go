package pipe

// TODO: support all the OTEL_ stuff here: https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md
type Config struct {
	OTELEndpoint        string `env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OTELMetricsEndpoint string `env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
	OTELTracesEndpoint  string `env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`
	PrintTraces         bool   `env:"PRINT_TRACES" envDefault:"true"` // TODO: false
	Exec                string `env:"EXECUTABLE_NAME"`
	FuncName            string `env:"INSTRUMENT_FUNC_NAME" envDefault:"net/http.HandlerFunc.ServeHTTP"`
}
