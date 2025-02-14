package main

import (
	"fmt"
	"os"

	"github.com/caarlos0/env/v9"
	gin2 "github.com/gin-gonic/gin"

	"github.com/grafana/beyla/v2/testserver_1.17/gin"
	"github.com/grafana/beyla/v2/testserver_1.17/gorilla"
	"github.com/grafana/beyla/v2/testserver_1.17/gorillamid"
	"github.com/grafana/beyla/v2/testserver_1.17/gorillamid2"
	grpctest "github.com/grafana/beyla/v2/testserver_1.17/grpc/server"
	"github.com/grafana/beyla/v2/testserver_1.17/std"
)

/*
Server implementation to be used by integration tests.
Basically it's a server that accepts any method and path with a set of query parameters
that allow modifying its behavior (duration, response...)
*/

type config struct {
	// STDPort to listen connections using the standard library
	STDPort int `env:"STD_PORT" envDefault:"8080"`
	// GinPort to listen connections using the Gin framework
	GinPort int `env:"GIN_PORT" envDefault:"8081"`
	// GorillaPort to listen connections using the Gorilla Mux framework
	GorillaPort int `env:"GORILLA_PORT" envDefault:"8082"`
	// GorillaPort to listen connections using the Gorilla Mux framework, but using a middleware that has custom ResposeWriter
	GorillaMidPort  int    `env:"GORILLA_MID_PORT" envDefault:"8083"`
	GorillaMid2Port int    `env:"GORILLA_MID2_PORT" envDefault:"8087"`
	LogLevel        string `env:"LOG_LEVEL" envDefault:"INFO"`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("can't load configuration from environment %w\n", err)
		os.Exit(-1)
	}

	wait := make(chan struct{})
	go func() {
		std.Setup(cfg.STDPort)
		close(wait)
	}()
	go func() {
		gin2.SetMode(gin2.ReleaseMode)
		gin.Setup(cfg.GinPort)
		close(wait)
	}()
	go func() {
		gorilla.Setup(cfg.GorillaPort, cfg.STDPort)
		close(wait)
	}()
	go func() {
		gorillamid.Setup(cfg.GorillaMidPort, cfg.STDPort)
		close(wait)
	}()
	go func() {
		gorillamid2.Setup(cfg.GorillaMid2Port, cfg.STDPort)
		close(wait)
	}()
	go func() {
		err := grpctest.Setup()
		if err != nil {
			fmt.Printf("HTTP server has unexpectedly stopped %w\n", err)
		}
		close(wait)
	}()

	// wait indefinitely unless any server crashes
	<-wait
	fmt.Printf("stopping process\n")
}
