package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/caarlos0/env/v7"
	"github.com/mariomac/distributed-service-example/backend/pkg/rest"
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
