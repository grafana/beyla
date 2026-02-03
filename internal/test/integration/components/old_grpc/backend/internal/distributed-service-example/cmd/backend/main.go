// Copied from
// https://github.com/mariomac/distributed-service-example/blob/af82ec3812c693167f8881490b9260d901c6a87d/backend/cmd/backend/main.go

package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caarlos0/env/v7"

	"github.com/grafana/beyla/v3/internal/test/integration/components/old_grpc/backend/internal/distributed-service-example/pkg/rest"
)

type Config struct {
	Port    int      `env:"PORT" envDefault:"8080"`
	Workers []string `env:"WORKERS"`
}

func main() {
	cfg := Config{}
	panicOnErr(env.Parse(&cfg))

	mux := http.ServeMux{}
	mux.Handle(rest.FactorialPath, rest.FactorialService(cfg.Workers, 5*time.Minute))

	err := http.ListenAndServe(fmt.Sprintf(":%d", cfg.Port), &mux)
	panicOnErr(err)
}

func panicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}
