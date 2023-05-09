package prom

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/prometheus/client_golang/prometheus"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
)

const (
	// trying to not collide with any of the ports listed here
	// https://github.com/prometheus/prometheus/wiki/Default-port-allocations
	defaultPort = 8999
	defaultPath = "/metrics"

	ReportRoutesCtxKey = "reportRoutes"
)

// using labels with equivalent names to OTEL attributes
var (
	httpMethodKey        = otelToProm(semconv.HTTPMethodKey)
	httpRouteKey         = otelToProm(semconv.HTTPRouteKey)
	httpStatusCodeKey    = otelToProm(semconv.HTTPStatusCodeKey)
	httpTargetKey        = otelToProm(semconv.HTTPTargetKey)
	netSockPeerAddrKey   = otelToProm(semconv.NetSockPeerAddrKey)
	netSockPeerNameKey   = otelToProm(semconv.NetSockPeerNameKey)
	netSockPeerPortKey   = otelToProm(semconv.NetSockPeerPortKey)
	rpcGRPCStatusCodeKey = otelToProm(semconv.RPCGRPCStatusCodeKey)
	rpcMethodKey         = otelToProm(semconv.RPCMethodKey)
	rpcSystemGRPC        = otelToProm(semconv.RPCSystemGRPC.Key)
)

func otelToProm(str attribute.Key) string {
	return strings.ReplaceAll(string(str), ".", "_")
}

// TODO: TLS
type PrometheusConfig struct {
	Port           int    `yaml:"port" env:"PROMETHEUS_PORT"`
	Path           string `yaml:"path" env:"PROMETHEUS_PATH"`
	ReportTarget   bool   `yaml:"report_target" env:"METRICS_REPORT_TARGET"`
	ReportPeerInfo bool   `yaml:"report_peer" env:"METRICS_REPORT_PEER"`
}

type metricsReporter struct {
	cfg          *PrometheusConfig
	registry     *prometheus.Registry
	reportRoutes bool

	httpDuration          *prometheus.HistogramVec
	httpClientDuration    *prometheus.HistogramVec
	grpcDuration          *prometheus.HistogramVec
	grpcClientDuration    *prometheus.HistogramVec
	httpRequestSize       *prometheus.HistogramVec
	httpClientRequestSize *prometheus.HistogramVec
}

func PullEndpointProvider(ctx context.Context, cfg *PrometheusConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.Path == "" {
		cfg.Path = defaultPath
	}
	reporter := newReporter(ctx, cfg)
	go reporter.serveHTTPMetrics()
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig) *metricsReporter {
	reportRoutes, _ := ctx.Value(ReportRoutesCtxKey).(bool)

	mr := &metricsReporter{
		cfg:          cfg,
		reportRoutes: reportRoutes,
		registry:     prometheus.NewRegistry(),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_server_duration_ms",
			Help: "duration of HTTP service calls from the server side, in milliseconds",
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_client_duration_ms",
			Help: "duration of HTTP service calls from the client side, in milliseconds",
		}, labelNamesHTTPClient(cfg)),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "rpc_server_duration_ms",
			Help: "duration of RCP service calls from the server side, in milliseconds",
		}, labelNamesGRPC(cfg)),
		grpcClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "rpc_client_duration_ms",
			Help: "duration of GRPC service calls from the client side, in milliseconds",
		}, labelNamesGRPC(cfg)),
		httpRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_server_request_size_bytes",
			Help: "size, in bytes, of the HTTP request body as received at the server side",
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: "http_client_request_size_bytes",
			Help: "size, in bytes, of the HTTP request body as sent from the client side",
		}, labelNamesHTTPClient(cfg)),
	}
	mr.registry.MustRegister(mr.httpClientRequestSize)
	mr.registry.MustRegister(mr.httpClientDuration)
	mr.registry.MustRegister(mr.grpcClientDuration)
	mr.registry.MustRegister(mr.httpRequestSize)
	mr.registry.MustRegister(mr.httpDuration)
	mr.registry.MustRegister(mr.grpcDuration)
	return mr
}

func (r *metricsReporter) reportMetrics(input <-chan []transform.HTTPRequestSpan) {
	for spans := range input {
		for i := range spans {
			r.record(&spans[i])
		}
	}
}

// labelNamesGRPC must return the label names in the same order as would be returned
// by labelValuesGRPC
func labelNamesGRPC(cfg *PrometheusConfig) []string {
	names := []string{rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesGRPC
func (r *metricsReporter) labelValuesGRPC(span *transform.HTTPRequestSpan) []string {
	// rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey
	names := []string{span.Path, "grpc", strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		names = append(names, span.Peer) // netSockPeerAddrKey
	}
	return names
}

// labelNamesHTTPClient must return the label names in the same order as would be returned
// by labelValuesHTTPClient
func labelNamesHTTPClient(cfg *PrometheusConfig) []string {
	names := []string{httpMethodKey, httpStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerNameKey, netSockPeerPortKey)
	}
	return names
}

// labelValuesHTTPClient must return the label names in the same order as would be returned
// by labelNamesHTTPClient
func (r *metricsReporter) labelValuesHTTPClient(span *transform.HTTPRequestSpan) []string {
	// httpMethodKey, httpStatusCodeKey
	names := []string{span.Method, strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		// netSockPeerAddrKey, netSockPeerPortKey
		names = append(names, span.Host, strconv.Itoa(span.HostPort))
	}
	return names
}

// labelNamesHTTP must return the label names in the same order as would be returned
// by labelValuesHTTP
func labelNamesHTTP(cfg *PrometheusConfig, reportRoutes bool) []string {
	names := []string{httpMethodKey, httpStatusCodeKey}
	if cfg.ReportTarget {
		names = append(names, httpTargetKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	if reportRoutes {
		names = append(names, httpRouteKey)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesHTTP
func (r *metricsReporter) labelValuesHTTP(span *transform.HTTPRequestSpan) []string {
	// httpMethodKey, httpStatusCodeKey
	names := []string{span.Method, strconv.Itoa(span.Status)}
	if r.cfg.ReportTarget {
		names = append(names, span.Path) // httpTargetKey
	}
	if r.cfg.ReportPeerInfo {
		names = append(names, span.Peer) // netSockPeerAddrKey
	}
	if r.reportRoutes {
		names = append(names, span.Route) // httpRouteKey
	}
	return names
}

func (r *metricsReporter) record(span *transform.HTTPRequestSpan) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds() * 1000
	switch span.Type {
	case transform.EventTypeHTTP:
		lv := r.labelValuesHTTP(span)
		r.httpDuration.WithLabelValues(lv...).Observe(duration)
		r.httpRequestSize.WithLabelValues(lv...).Observe(float64(span.ContentLength))
	case transform.EventTypeHTTPClient:
		lv := r.labelValuesHTTPClient(span)
		r.httpClientDuration.WithLabelValues(lv...).Observe(duration)
		r.httpClientRequestSize.WithLabelValues(lv...).Observe(float64(span.ContentLength))
	case transform.EventTypeGRPC:
		r.grpcDuration.WithLabelValues(r.labelValuesGRPC(span)...).Observe(duration)
	case transform.EventTypeGRPCClient:
		r.grpcClientDuration.WithLabelValues(r.labelValuesGRPC(span)...).Observe(duration)
	}
}

func (r *metricsReporter) serveHTTPMetrics() {
	log := slog.With("component", "prom.MetricsReporter")
	mux := http.NewServeMux()
	mux.Handle(r.cfg.Path, promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{Registry: r.registry}))
	log.Info("opening prometheus scrape endpoint", "port", r.cfg.Port, "path", r.cfg.Path)
	err := http.ListenAndServe(fmt.Sprintf(":%d", r.cfg.Port), nil)
	if err == http.ErrServerClosed {
		log.Debug("HTTP server was closed", "err", err)
	} else {
		log.Error("HTTP service ended unexpectedly", err)
	}
}
