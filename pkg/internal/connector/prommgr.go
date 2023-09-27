// Package connector provides tools for sharing the connection of diverse exporters
// (Prometheus, OTEL...) from different nodes
package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func log() *slog.Logger {
	return slog.With("component", "connector.PrometheusManager")
}

// PrometheusManager allows exporting metrics from different sources (instrumented metrics, internal metrics...)
// sharing the same port and path, or using different ones, depending on the configuration provided by the registrars.
type PrometheusManager struct {
	started atomic.Bool
	// key 1: port. Key 2: path
	registries map[int]map[string]*prometheus.Registry

	metrics internalIntrumenter
}

type internalIntrumenter interface {
	PrometheusRequest(port, path string)
}

func (pm *PrometheusManager) InstrumentWith(ii internalIntrumenter) {
	pm.metrics = ii
}

// Register a set of prometheus metrics to be accessible through an HTTP port/path.
// This method is not thread-safe
func (pm *PrometheusManager) Register(port int, path string, collectors ...prometheus.Collector) {
	log().Debug("registering Prometheus metrics collectors",
		"len", len(collectors), "port", port, "path", path)
	if pm.registries == nil {
		pm.registries = map[int]map[string]*prometheus.Registry{}
	}
	paths, ok := pm.registries[port]
	if !ok {
		paths = map[string]*prometheus.Registry{}
		pm.registries[port] = paths
	}
	reg, ok := paths[path]
	if !ok {
		reg = prometheus.NewRegistry()
		paths[path] = reg
	}
	reg.MustRegister(collectors...)
}

// StartHTTP serves metrics in background. Its invocation won't have effect if it has been invoked previously,
// so invoke it only after you are sure that all the collectors have been registered via the Register method.
func (pm *PrometheusManager) StartHTTP(ctx context.Context) {
	if pm.started.Swap(true) {
		return
	}
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
		pm.listenAndServe(ctx, port, mux)
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

func (pm *PrometheusManager) listenAndServe(ctx context.Context, port int, handler http.Handler) {
	// TODO: support TLS configuration
	server := http.Server{Addr: fmt.Sprintf(":%d", port), Handler: handler}
	log := log().With("port", port)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			log.Debug("HTTP server was closed", "err", err)
		} else {
			log.Error("HTTP service ended unexpectedly", err)
		}
	}()
	go func() {
		<-ctx.Done()
		if err := server.Close(); err != nil {
			log.Warn("error closing HTTP server", "err", err.Error())
		}
	}()
}
