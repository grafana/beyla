package main

import (
	"log/slog"
	"os"

	"github.com/caarlos0/env/v9"
	gin2 "github.com/gin-gonic/gin"

	"github.com/grafana/beyla/test/integration/components/testserver/gin"
	"github.com/grafana/beyla/test/integration/components/testserver/gorilla"
	"github.com/grafana/beyla/test/integration/components/testserver/gorillamid"
	"github.com/grafana/beyla/test/integration/components/testserver/gorillamid2"
	grpctest "github.com/grafana/beyla/test/integration/components/testserver/grpc/server"
	"github.com/grafana/beyla/test/integration/components/testserver/std"
)

/*
Server implementation to be used by integration tests.
Basically it's a server that accepts any method and path with a set of query parameters
that allow modifying its behavior (duration, response...)
*/

type config struct {
	// STDPort to listen connections using the standard library
	STDPort int `env:"STD_PORT" envDefault:"8080"`
	// STDPort to listen connections using the standard library
	STDTLSPort int `env:"STD_TLS_PORT" envDefault:"8383"`
	// GinPort to listen connections using the Gin framework
	GinPort int `env:"GIN_PORT" envDefault:"8081"`
	// GorillaPort to listen connections using the Gorilla Mux framework
	GorillaPort int `env:"GORILLA_PORT" envDefault:"8082"`
	// GorillaPort to listen connections using the Gorilla Mux framework, but using a middleware that has custom ResposeWriter
	GorillaMidPort  int    `env:"GORILLA_MID_PORT" envDefault:"8083"`
	GorillaMid2Port int    `env:"GORILLA_MID2_PORT" envDefault:"8087"`
	GRPCPort        int    `env:"GRPC_PORT" envDefault:"5051"`
	GRPCTLSPort     int    `env:"GRPC_TLS_PORT" envDefault:"50051"`
	LogLevel        string `env:"LOG_LEVEL" envDefault:"INFO"`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("can't load configuration from environment", "error", err)
		os.Exit(-1)
	}
	setupLog(&cfg)

	wait := make(chan struct{})
	go func() {
		std.Setup(cfg.STDPort)
		close(wait)
	}()
	go func() {
		std.SetupTLS(cfg.STDTLSPort)
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
		err := grpctest.Setup(cfg.GRPCPort)
		if err != nil {
			slog.Error("HTTP server has unexpectedly stopped", "error", err)
		}
		close(wait)
	}()

	go func() {
		err := grpctest.SetupTLS(cfg.GRPCTLSPort)
		if err != nil {
			slog.Error("HTTP server has unexpectedly stopped", "error", err)
		}
		close(wait)
	}()

	// wait indefinitely unless any server crashes
	<-wait
	slog.Warn("stopping process")
}

func setupLog(cfg *config) {
	lvl := slog.LevelInfo
	err := lvl.UnmarshalText([]byte(cfg.LogLevel))
	if err != nil {
		slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", "error", err)
		os.Exit(-1)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	})))
	slog.Debug("logger is set", "level", lvl.String())
}
