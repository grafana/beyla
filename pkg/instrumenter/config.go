package instrumenter

type Config struct {
	MetricsEndpoint string `env:"OTEL_METRICS_ENDPOINT"`
	TracesEndpoint  string `env:"OTEL_TRACES_ENDPOINT"`
	PrintTraces     bool   `env:"PRINT_TRACES" envDefault:"true"` // TODO: false
	Exec            string `env:"EXECUTABLE_NAME"`
	FuncName        string `env:"INSTRUMENT_FUNC_NAME" envDefault:"net/http.HandlerFunc.ServeHTTP"`
}
