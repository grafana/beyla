package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/caarlos0/env"
	"golang.org/x/exp/slog"
)

/*
Server implementation to be used by integration tests.
Basically it's a server that accepts any method and path with a set of query parameters
that allow modifying its behavior (duration, response...)
*/

const (
	// argDelay allows delaying the response of a service call (default: no delay)
	argDelay = "delay"
	// argStatus allows specifying the status response of a service call (default: 200)
	argStatus = "status"
)

type config struct {
	Port     int    `env:"SVC_PORT" envDefault:"8080"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"INFO"`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		slog.Error("can't load configuration from environment", err)
		os.Exit(-1)
	}
	setupLog(&cfg)

	address := fmt.Sprintf(":%d", cfg.Port)
	slog.Info("starting HTTP server", "address", address)
	err := http.ListenAndServe(address, http.HandlerFunc(httpHandler))
	slog.Error("HTTP server has unexpectedly stopped", err)
}

func setupLog(cfg *config) {
	lvl := slog.LevelInfo
	err := lvl.UnmarshalText([]byte(cfg.LogLevel))
	if err != nil {
		slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", err)
		os.Exit(-1)
	}
	ho := slog.HandlerOptions{
		Level: lvl,
	}
	slog.SetDefault(slog.New(ho.NewTextHandler(os.Stderr)))
	slog.Debug("logger is set", "level", lvl.String())
}

func httpHandler(rw http.ResponseWriter, req *http.Request) {
	slog.Debug("received request", "url", req.RequestURI)
	status := http.StatusOK
	for k, v := range req.URL.Query() {
		if len(v) == 0 {
			continue
		}
		switch k {
		case argStatus:
			if s, err := strconv.Atoi(v[0]); err != nil {
				slog.Debug("wrong status value. Ignoring", "error", err)
			} else {
				status = s
			}
		case argDelay:
			if d, err := time.ParseDuration(v[0]); err != nil {
				slog.Debug("wrong delay value. Ignoring", "error", err)
			} else {
				time.Sleep(d)
			}
		}
	}
	rw.WriteHeader(status)
}
