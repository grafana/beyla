package prom

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	HTTPServerDuration    = "http_server_duration_seconds"
	HTTPClientDuration    = "http_client_duration_seconds"
	RPCServerDuration     = "rpc_server_duration_seconds"
	RPCClientDuration     = "rpc_client_duration_seconds"
	HTTPServerRequestSize = "http_server_request_size_bytes"
	HTTPClientRequestSize = "http_client_request_size_bytes"

	serviceNameKey       = "service_name"
	httpMethodKey        = "http_method"
	httpRouteKey         = "http_route"
	httpStatusCodeKey    = "http_status_code"
	httpTargetKey        = "http_target"
	netSockPeerAddrKey   = "net_sock_peer_addr"
	netSockPeerNameKey   = "net_sock_peer_name"
	netSockPeerPortKey   = "net_sock_peer_port"
	rpcGRPCStatusCodeKey = "rpc_grpc_status_code"
	rpcMethodKey         = "rpc_method"
	rpcSystemGRPC        = "rpc_system"
)

// TODO: TLS
type PrometheusConfig struct {
	ServiceName    string `yaml:"service_name" env:"PROMETHEUS_SERVICE_NAME"`
	Port           int    `yaml:"port" env:"PROMETHEUS_PORT"`
	Path           string `yaml:"path" env:"PROMETHEUS_PATH"`
	ReportTarget   bool   `yaml:"report_target" env:"METRICS_REPORT_TARGET"`
	ReportPeerInfo bool   `yaml:"report_peer" env:"METRICS_REPORT_PEER"`
}

func (p PrometheusConfig) Enabled() bool {
	return p.Port != 0
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

func PrometheusEndpointProvider(ctx context.Context, cfg PrometheusConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	reporter := newReporter(ctx, &cfg)
	go reporter.serveHTTPMetrics()
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig) *metricsReporter {
	ctxInfo := global.Context(ctx)
	reportRoutes := ctxInfo.ReportRoutes
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	if cfg.ServiceName == "" {
		cfg.ServiceName = ctxInfo.ServiceName
	}

	mr := &metricsReporter{
		cfg:          cfg,
		reportRoutes: reportRoutes,
		registry:     prometheus.NewRegistry(),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: HTTPServerDuration,
			Help: "duration of HTTP service calls from the server side, in milliseconds",
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: HTTPClientDuration,
			Help: "duration of HTTP service calls from the client side, in milliseconds",
		}, labelNamesHTTPClient(cfg)),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: RPCServerDuration,
			Help: "duration of RCP service calls from the server side, in milliseconds",
		}, labelNamesGRPC(cfg)),
		grpcClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: RPCClientDuration,
			Help: "duration of GRPC service calls from the client side, in milliseconds",
		}, labelNamesGRPC(cfg)),
		httpRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: HTTPServerRequestSize,
			Help: "size, in bytes, of the HTTP request body as received at the server side",
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: HTTPClientRequestSize,
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
			r.observe(&spans[i])
		}
	}
}

func (r *metricsReporter) observe(span *transform.HTTPRequestSpan) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
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

// labelNamesGRPC must return the label names in the same order as would be returned
// by labelValuesGRPC
func labelNamesGRPC(cfg *PrometheusConfig) []string {
	names := []string{serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesGRPC
func (r *metricsReporter) labelValuesGRPC(span *transform.HTTPRequestSpan) []string {
	// serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey
	names := []string{r.cfg.ServiceName, span.Path, "grpc", strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		names = append(names, span.Peer) // netSockPeerAddrKey
	}
	return names
}

// labelNamesHTTPClient must return the label names in the same order as would be returned
// by labelValuesHTTPClient
func labelNamesHTTPClient(cfg *PrometheusConfig) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerNameKey, netSockPeerPortKey)
	}
	return names
}

// labelValuesHTTPClient must return the label names in the same order as would be returned
// by labelNamesHTTPClient
func (r *metricsReporter) labelValuesHTTPClient(span *transform.HTTPRequestSpan) []string {
	// httpMethodKey, httpStatusCodeKey
	names := []string{r.cfg.ServiceName, span.Method, strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		// netSockPeerAddrKey, netSockPeerPortKey
		names = append(names, span.Host, strconv.Itoa(span.HostPort))
	}
	return names
}

// labelNamesHTTP must return the label names in the same order as would be returned
// by labelValuesHTTP
func labelNamesHTTP(cfg *PrometheusConfig, reportRoutes bool) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
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
	names := []string{r.cfg.ServiceName, span.Method, strconv.Itoa(span.Status)}
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

// serveHTTPMetrics opens a Prometheus scraping HTTP endpoint to expose the metrics
func (r *metricsReporter) serveHTTPMetrics() {
	log := slog.With("component", "prom.MetricsReporter", "port", r.cfg.Port, "path", r.cfg.Path)
	log.Info("opening prometheus scrape endpoint")
	mux := http.NewServeMux()
	promHandler := promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{Registry: r.registry})
	if log.Enabled(slog.LevelDebug) {
		mux.Handle(r.cfg.Path, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			log.Debug("received request in metrics endpoint", "uri", req.RequestURI, "remoteAddr", req.RemoteAddr)
			promHandler.ServeHTTP(rw, req)
		}))
	} else {
		mux.Handle(r.cfg.Path, promHandler)
	}
	err := http.ListenAndServe(fmt.Sprintf(":%d", r.cfg.Port), mux)
	if err == http.ErrServerClosed {
		log.Debug("HTTP server was closed", "err", err)
	} else {
		log.Error("HTTP service ended unexpectedly", err)
	}
}
