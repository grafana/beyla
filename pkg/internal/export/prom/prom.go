package prom

import (
	"context"
	"strconv"
	"strings"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/connector"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/export/otel"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/internal/transform"
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
)

// TODO: TLS
type PrometheusConfig struct {
	ServiceName      string `yaml:"service_name" env:"PROMETHEUS_SERVICE_NAME"`
	ServiceNamespace string `yaml:"service_namespace" env:"SERVICE_NAMESPACE"`

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
	cfg          *PrometheusConfig
	reportRoutes bool

	httpDuration          *prometheus.HistogramVec
	httpClientDuration    *prometheus.HistogramVec
	grpcDuration          *prometheus.HistogramVec
	grpcClientDuration    *prometheus.HistogramVec
	httpRequestSize       *prometheus.HistogramVec
	httpClientRequestSize *prometheus.HistogramVec

	promConnect *connector.PrometheusManager

	bgCtx context.Context
}

func PrometheusEndpoint(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	reporter := newReporter(ctx, cfg, ctxInfo)
	return reporter.reportMetrics, nil
}

func newReporter(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) *metricsReporter {
	reportRoutes := ctxInfo.ReportRoutes
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	if cfg.ServiceName == "" {
		cfg.ServiceName = ctxInfo.ServiceName
	}
	mr := &metricsReporter{
		bgCtx:        ctx,
		cfg:          cfg,
		reportRoutes: reportRoutes,
		promConnect:  ctxInfo.Prometheus,
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPServerDuration,
			Help:    "duration of HTTP service calls from the server side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPClientDuration,
			Help:    "duration of HTTP service calls from the client side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesHTTPClient(cfg)),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    RPCServerDuration,
			Help:    "duration of RCP service calls from the server side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesGRPC(cfg)),
		grpcClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    RPCClientDuration,
			Help:    "duration of GRPC service calls from the client side, in seconds",
			Buckets: cfg.Buckets.DurationHistogram,
		}, labelNamesGRPC(cfg)),
		httpRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPServerRequestSize,
			Help:    "size, in bytes, of the HTTP request body as received at the server side",
			Buckets: cfg.Buckets.RequestSizeHistogram,
		}, labelNamesHTTP(cfg, reportRoutes)),
		httpClientRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    HTTPClientRequestSize,
			Help:    "size, in bytes, of the HTTP request body as sent from the client side",
			Buckets: cfg.Buckets.RequestSizeHistogram,
		}, labelNamesHTTPClient(cfg)),
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

func (r *metricsReporter) reportMetrics(input <-chan []transform.HTTPRequestSpan) {
	go r.promConnect.StartHTTP(r.bgCtx)
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
		lv := r.labelsHTTPServer(span)
		r.httpDuration.With(lv).Observe(duration)
		r.httpRequestSize.With(lv).Observe(float64(span.ContentLength))
	case transform.EventTypeHTTPClient:
		lv := r.labelsHTTPClient(span)
		r.httpClientDuration.With(lv).Observe(duration)
		r.httpClientRequestSize.With(lv).Observe(float64(span.ContentLength))
	case transform.EventTypeGRPC:
		r.grpcDuration.With(r.labelsGRPC(span)).Observe(duration)
	case transform.EventTypeGRPCClient:
		r.grpcClientDuration.With(r.labelsGRPC(span)).Observe(duration)
	}
}

func labelNamesGRPC(cfg *PrometheusConfig) []string {
	names := []string{serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if cfg.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	return appendK8sMetrics(names)
}

func (r *metricsReporter) labelsGRPC(span *transform.HTTPRequestSpan) prometheus.Labels {
	// In some situations e.g. system-wide instrumentation, the global service name
	// is empty and we need to take the name from the trace
	var svcName = r.cfg.ServiceName
	if svcName == "" {
		svcName = span.ServiceName
	}
	lbls := prometheus.Labels{
		serviceNameKey:       svcName,
		rpcMethodKey:         span.Path,
		rpcSystemGRPC:        "grpc",
		rpcGRPCStatusCodeKey: strconv.Itoa(span.Status),
	}
	if r.cfg.ServiceNamespace != "" {
		lbls[serviceNamespaceKey] = r.cfg.ServiceNamespace
	}
	if r.cfg.ReportPeerInfo {
		lbls[netSockPeerAddrKey] = span.Peer
	}
	addMetadata(lbls, span)
	return lbls
}

func labelNamesHTTPClient(cfg *PrometheusConfig) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
	if cfg.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerNameKey, netSockPeerPortKey)
	}
	return appendK8sMetrics(names)
}

func (r *metricsReporter) labelsHTTPClient(span *transform.HTTPRequestSpan) prometheus.Labels {
	lbls := prometheus.Labels{
		serviceNameKey:    r.cfg.ServiceName,
		httpMethodKey:     span.Method,
		httpStatusCodeKey: strconv.Itoa(span.Status),
	}

	if r.cfg.ServiceNamespace != "" {
		lbls[serviceNamespaceKey] = r.cfg.ServiceNamespace
	}
	if r.cfg.ReportPeerInfo {
		// netSockPeerAddrKey, netSockPeerPortKey
		lbls[netSockPeerNameKey] = span.Host
		lbls[netSockPeerPortKey] = strconv.Itoa(span.HostPort)
	}
	addMetadata(lbls, span)
	return lbls
}

func labelNamesHTTP(cfg *PrometheusConfig, reportRoutes bool) []string {
	names := []string{serviceNameKey, httpMethodKey, httpStatusCodeKey}
	if cfg.ServiceNamespace != "" {
		names = append(names, serviceNamespaceKey)
	}
	if cfg.ReportTarget {
		names = append(names, httpTargetKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, netSockPeerAddrKey)
	}
	if reportRoutes {
		names = append(names, httpRouteKey)
	}
	return appendK8sMetrics(names)
}

func appendK8sMetrics(names []string) []string {
	return append(names, "k8s_src_name", "k8s_dst_name", "k8s_src_namespace", "k8s_dst_namespace", "k8s_dst_type")
}

func (r *metricsReporter) labelsHTTPServer(span *transform.HTTPRequestSpan) prometheus.Labels {
	lbls := prometheus.Labels{
		serviceNameKey:    r.cfg.ServiceName,
		httpMethodKey:     span.Method,
		httpStatusCodeKey: strconv.Itoa(span.Status),
	}

	if r.cfg.ServiceNamespace != "" {
		lbls[serviceNamespaceKey] = r.cfg.ServiceNamespace
	}
	if r.cfg.ReportTarget {
		lbls[httpTargetKey] = span.Path
	}
	if r.cfg.ReportPeerInfo {
		lbls[netSockPeerAddrKey] = span.Peer
	}
	if r.reportRoutes {
		lbls[httpRouteKey] = span.Route
	}
	addMetadata(lbls, span)
	return lbls
}

func addMetadata(lbls prometheus.Labels, span *transform.HTTPRequestSpan) {
	for _, md := range span.Metadata {
		for k, v := range md {
			// TODO: see if we can optimize this
			lbls[strings.ReplaceAll(k, ".", "_")] = v
		}
	}
}
