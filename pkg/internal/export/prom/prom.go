package prom

import (
	"context"
	"strconv"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/transform"
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
	serviceNamespaceKey  = "service_namespace"
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

	k8sSrcNameKey      = "k8s_src_name"
	k8sSrcNamespaceKey = "k8s_src_namespace"
	k8sDstNameKey      = "k8s_dst_name"
	k8sDstNamespaceKey = "k8s_dst_namespace"
	k8sDstTypeKey      = "k8s_dst_type"
)

// TODO: TLS
type PrometheusConfig struct {
	Port           int    `yaml:"port" env:"BEYLA_PROMETHEUS_PORT"`
	Path           string `yaml:"path" env:"PROMETHEUS_PATH"`
	ReportTarget   bool   `yaml:"report_target" env:"METRICS_REPORT_TARGET"`
	ReportPeerInfo bool   `yaml:"report_peer" env:"METRICS_REPORT_PEER"`

	Buckets otel.Buckets `yaml:"buckets"`
}

// nolint:gocritic
func (p PrometheusConfig) Enabled() bool {
	return p.Port != 0
}

type metricsReporter struct {
	cfg *PrometheusConfig

	httpDuration          *prometheus.HistogramVec
	httpClientDuration    *prometheus.HistogramVec
	grpcDuration          *prometheus.HistogramVec
	grpcClientDuration    *prometheus.HistogramVec
	httpRequestSize       *prometheus.HistogramVec
	httpClientRequestSize *prometheus.HistogramVec

	promConnect *connector.PrometheusManager

	bgCtx   context.Context
	ctxInfo *global.ContextInfo
}

func PrometheusEndpoint(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]request.Span], error) {
	reporter := newReporter(ctx, cfg, ctxInfo)
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) *metricsReporter {
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &metricsReporter{
		bgCtx:       ctx,
		ctxInfo:     ctxInfo,
		cfg:         cfg,
		promConnect: ctxInfo.Prometheus,
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPServerDuration,
			Help:    "duration of HTTP service calls from the server side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesHTTP(cfg, ctxInfo)),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPClientDuration,
			Help:    "duration of HTTP service calls from the client side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesHTTPClient(cfg, ctxInfo)),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    RPCServerDuration,
			Help:    "duration of RCP service calls from the server side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesGRPC(cfg, ctxInfo)),
		grpcClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    RPCClientDuration,
			Help:    "duration of GRPC service calls from the client side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesGRPC(cfg, ctxInfo)),
		httpRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPServerRequestSize,
			Help:    "size, in bytes, of the HTTP request body as received at the server side",
			Buckets: cfg.Buckets.RequestSizeHistogram,
		}, labelNamesHTTP(cfg, ctxInfo)),
		httpClientRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPClientRequestSize,
			Help:    "size, in bytes, of the HTTP request body as sent from the client side",
			Buckets: cfg.Buckets.RequestSizeHistogram,
		}, labelNamesHTTPClient(cfg, ctxInfo)),
	}
	mr.promConnect.Register(cfg.Port, cfg.Path,
		mr.httpClientRequestSize,
		mr.httpClientDuration,
		mr.grpcClientDuration,
		mr.httpRequestSize,
		mr.httpDuration,
		mr.grpcDuration)
	return mr
}

func (r *metricsReporter) reportMetrics(input <-chan []request.Span) {
	go r.promConnect.StartHTTP(r.bgCtx)
	for spans := range input {
		for i := range spans {
			r.observe(&spans[i])
		}
	}
}

func (r *metricsReporter) observe(span *request.Span) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
	switch span.Type {
	case request.EventTypeHTTP:
		lv := r.labelValuesHTTP(span)
		r.httpDuration.WithLabelValues(lv...).Observe(duration)
		r.httpRequestSize.WithLabelValues(lv...).Observe(float64(span.ContentLength))
	case request.EventTypeHTTPClient:
		lv := r.labelValuesHTTPClient(span)
		r.httpClientDuration.WithLabelValues(lv...).Observe(duration)
		r.httpClientRequestSize.WithLabelValues(lv...).Observe(float64(span.ContentLength))
	case request.EventTypeGRPC:
		r.grpcDuration.WithLabelValues(r.labelValuesGRPC(span)...).Observe(duration)
	case request.EventTypeGRPCClient:
		r.grpcClientDuration.WithLabelValues(r.labelValuesGRPC(span)...).Observe(duration)
	}
}

// labelNamesGRPC must return the label names in the same order as would be returned
// by labelValuesGRPC
func labelNamesGRPC(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	names := []string{serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if ctxInfo.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	if ctxInfo.K8sDecoration {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesGRPC
func (r *metricsReporter) labelValuesGRPC(span *request.Span) []string {
	// serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey
	values := []string{span.ServiceName, span.Path, "grpc", strconv.Itoa(span.Status)}
	if r.ctxInfo.ServiceNamespace != "" {
		values = append(values, r.ctxInfo.ServiceNamespace)
	}
	if r.cfg.ReportPeerInfo {
		values = append(values, span.Peer) // netSockPeerAddrKey
	}
	if r.ctxInfo.K8sDecoration {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

// labelNamesHTTPClient must return the label names in the same order as would be returned
// by labelValuesHTTPClient
func labelNamesHTTPClient(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
	if ctxInfo.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerNameKey, netSockPeerPortKey)
	}
	if ctxInfo.K8sDecoration {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesHTTPClient must return the label names in the same order as would be returned
// by labelNamesHTTPClient
func (r *metricsReporter) labelValuesHTTPClient(span *request.Span) []string {
	// httpMethodKey, httpStatusCodeKey
	values := []string{span.ServiceName, span.Method, strconv.Itoa(span.Status)}
	if r.ctxInfo.ServiceNamespace != "" {
		values = append(values, r.ctxInfo.ServiceNamespace)
	}
	if r.cfg.ReportPeerInfo {
		// netSockPeerAddrKey, netSockPeerPortKey
		values = append(values, span.Host, strconv.Itoa(span.HostPort))
	}
	if r.ctxInfo.K8sDecoration {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

// labelNamesHTTP must return the label names in the same order as would be returned
// by labelValuesHTTP
func labelNamesHTTP(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
	if ctxInfo.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportTarget {
		names = append(names, httpTargetKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	if ctxInfo.ReportRoutes {
		names = append(names, httpRouteKey)
	}
	if ctxInfo.K8sDecoration {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesHTTP
func (r *metricsReporter) labelValuesHTTP(span *request.Span) []string {
	// httpMethodKey, httpStatusCodeKey
	values := []string{span.ServiceName, span.Method, strconv.Itoa(span.Status)}
	if r.ctxInfo.ServiceNamespace != "" {
		values = append(values, r.ctxInfo.ServiceNamespace)
	}
	if r.cfg.ReportTarget {
		values = append(values, span.Path) // httpTargetKey
	}
	if r.cfg.ReportPeerInfo {
		values = append(values, span.Peer) // netSockPeerAddrKey
	}
	if r.ctxInfo.ReportRoutes {
		values = append(values, span.Route) // httpRouteKey
	}
	if r.ctxInfo.K8sDecoration {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

func appendK8sLabelNames(names []string) []string {
	names = append(names, k8sSrcNameKey, k8sSrcNamespaceKey, k8sDstNameKey, k8sDstNamespaceKey, k8sDstTypeKey)
	return names
}

func appendK8sLabelValues(values []string, span *request.Span) []string {
	// k8sSrcNameKey, k8sSrcNamespaceKey, k8sDstNameKey, k8sDstNamespaceKey, k8sDstTypeKey
	values = append(values,
		span.Metadata[transform.SrcNameKey],
		span.Metadata[transform.SrcNamespaceKey],
		span.Metadata[transform.DstNameKey],
		span.Metadata[transform.DstNamespaceKey],
		span.Metadata[transform.DstTypeKey],
	)
	return values
}
