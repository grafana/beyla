package instrumenter

type Config struct {
	Endpoint string `env:"OTEL_TRACES_ENDPOINT"`
	Exec     string `env:"EXECUTABLE_NAME"`
	FuncName string `env:"INSTRUMENT_FUNC_NAME" envDefault:"net/http.HandlerFunc.ServeHTTP"`
}

