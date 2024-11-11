package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	path        = "/ping"
	arg         = "msg"
	delayArg    = "delay"
	envPort     = "SERVER_PORT"
	defaultPort = 8080
)

func pingHandler(rw http.ResponseWriter, req *http.Request) {
	slog.Debug("connection established", "remoteAddr", req.RemoteAddr)
	if req.URL.Path != path {
		slog.Info("not found", "url", req.URL)
		rw.WriteHeader(http.StatusNotFound)
		return
	}
	ret := "PONG!"
	if req.URL.Query().Has(arg) {
		ret = req.URL.Query().Get(arg)
	}

	if req.URL.Query().Has(delayArg) {
		delay, _ := time.ParseDuration(req.URL.Query().Get(delayArg))
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	rw.WriteHeader(http.StatusOK)
	b, err := rw.Write([]byte(ret))
	if err != nil {
		slog.Error("writing response", "error", err, "url", req.URL)
		return
	}
	slog.Debug(fmt.Sprintf("%T", rw))
	slog.Debug("written response", "url", req.URL, slog.Int("bytes", b))
}

func main() {
	// Use INFO as default log
	lvl := slog.LevelInfo
	args := os.Args

	lvlEnv, ok := os.LookupEnv("LOG_LEVEL")
	// LOG_LEVEL is set, let's default to the desired level
	if ok {
		err := lvl.UnmarshalText([]byte(lvlEnv))
		if err != nil {
			slog.Error("unknown log level specified, choises are [DEBUG, INFO, WARN, ERROR]", "error", errors.New(lvlEnv))
			os.Exit(-1)
		}
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: lvl,
	})))

	port := defaultPort
	if ps, ok := os.LookupEnv(envPort); ok {
		var err error
		if port, err = strconv.Atoi(ps); err != nil {
			slog.Error("parsing port", "error", err, "value", ps)
			os.Exit(-1)
		}
	}
	slog.Info("listening and serving", "port", port, "process_id", os.Getpid())
	if len(args) > 1 && args[1] == "ssl" {
		slog.Info("TLS enabled")
		panic(http.ListenAndServeTLS(fmt.Sprintf(":%d", port), "server.crt", "server.key", http.HandlerFunc(pingHandler)))
	}
	panic(http.ListenAndServe(fmt.Sprintf(":%d", port), http.HandlerFunc(pingHandler)))
}
