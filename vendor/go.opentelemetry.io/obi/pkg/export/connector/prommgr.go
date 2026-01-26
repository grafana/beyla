// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package connector provides tools for sharing the connection of diverse exporters
// (Prometheus, OTEL...) from different nodes
package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
)

func log() *slog.Logger {
	return slog.With("component", "connector.PrometheusManager")
}

// PrometheusManager allows exporting metrics from different sources (instrumented metrics, internal metrics...)
// sharing the same port and path, or using different ones, depending on the configuration provided by the registrars.
type PrometheusManager struct {
	mt      sync.Mutex
	started bool
	// key 1: port. Key 2: path
	registries maps.Map2[int, string, *prometheus.Registry]

	metrics internalIntrumenter
}

type internalIntrumenter interface {
	PrometheusRequest(port, path string)
}

func (pm *PrometheusManager) InstrumentWith(ii internalIntrumenter) {
	pm.mt.Lock()
	defer pm.mt.Unlock()
	pm.metrics = ii
}

// Register a set of prometheus metrics to be accessible through an HTTP port/path.
// This method is not thread-safe
func (pm *PrometheusManager) Register(port int, path string, collectors ...prometheus.Collector) {
	pm.mt.Lock()
	defer pm.mt.Unlock()
	log().Debug("registering Prometheus metrics collectors",
		"len", len(collectors), "port", port, "path", path)

	if pm.registries == nil {
		pm.registries = maps.Map2[int, string, *prometheus.Registry]{}
	}
	reg, ok := pm.registries.Get(port, path)
	if !ok {
		reg = prometheus.NewRegistry()
		pm.registries.Put(port, path, reg)
	}
	reg.MustRegister(collectors...)
}

// StartHTTP serves metrics in background. Its invocation won't have effect if it has been invoked previously,
// so invoke it only after you are sure that all the collectors have been registered via the Register method.
func (pm *PrometheusManager) StartHTTP(ctx context.Context) {
	pm.mt.Lock()
	defer pm.mt.Unlock()
	if pm.started {
		return
	}
	pm.started = true

	log := log()
	// Creating a serve mux for each port
	for port, paths := range pm.registries {
		mux := http.NewServeMux()
		for path, registry := range paths {
			log.With("port", port, "path", path).Info("opening prometheus scrape endpoint")
			promHandler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry})
			promHandler = wrapDebugHandler(log, promHandler)
			promHandler = wrapInstrumentedHandler(pm.metrics, port, path, promHandler)
			mux.Handle(path, promHandler)
		}
		listenAndServe(ctx, port, mux)
	}
}

func wrapInstrumentedHandler(metrics internalIntrumenter, port int, path string, promHandler http.Handler) http.HandlerFunc {
	// we don't wrap anything if the reporter is nil
	if metrics == nil {
		return promHandler.ServeHTTP
	}
	portStr := strconv.Itoa(port)
	return func(rw http.ResponseWriter, req *http.Request) {
		promHandler.ServeHTTP(rw, req)
		metrics.PrometheusRequest(portStr, path)
	}
}

func wrapDebugHandler(log *slog.Logger, promHandler http.Handler) http.HandlerFunc {
	// we don't wrap anything for if the log level is not debug or lower
	if !log.Enabled(context.TODO(), slog.LevelDebug) {
		return promHandler.ServeHTTP
	}
	return func(rw http.ResponseWriter, req *http.Request) {
		log.Debug("received metrics request", "uri", req.RequestURI, "remoteAddr", req.RemoteAddr)
		promHandler.ServeHTTP(rw, req)
	}
}

func listenAndServe(ctx context.Context, port int, handler http.Handler) {
	// TODO: support TLS configuration
	server := http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler}
	log := log().With("port", port)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			log.Debug("Prometheus endpoint server was closed", "error", err)
		} else {
			log.Error("Prometheus endpoint service ended unexpectedly", "error", err)
			err = syscall.Kill(os.Getpid(), syscall.SIGINT) // interrupt for graceful shutdown, instead of os.Exit
			if err != nil {
				log.Error("unable to terminate", "error", err)
			}
		}
	}()
	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			log.Warn("error closing HTTP server", "err", err.Error())
		}
	}()
}
