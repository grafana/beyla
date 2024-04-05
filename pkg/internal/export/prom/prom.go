package prom

import (
	"context"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/buildinfo"
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	HTTPServerDuration    = "http_server_request_duration_seconds"
	HTTPClientDuration    = "http_client_request_duration_seconds"
	RPCServerDuration     = "rpc_server_duration_seconds"
	RPCClientDuration     = "rpc_client_duration_seconds"
	SQLClientDuration     = "sql_client_duration_seconds"
	HTTPServerRequestSize = "http_server_request_body_size_bytes"
	HTTPClientRequestSize = "http_client_request_body_size_bytes"

	// target will expose the process hostname-pid (or K8s Pod).
	// It is advised for users that to use relabeling rules to
	// override the "instance" attribute with "target" in the
	// Prometheus server. This would be similar to the "multi target pattern":
	// https://prometheus.io/docs/guides/multi-target-exporter/
	targetInstanceKey    = "target_instance"
	serviceNameKey       = "service_name"
	serviceNamespaceKey  = "service_namespace"
	httpMethodKey        = "http_request_method"
	httpRouteKey         = "http_route"
	httpStatusCodeKey    = "http_response_status_code"
	httpTargetKey        = "url_path"
	clientAddrKey        = "client_address"
	serverAddrKey        = "server_address"
	serverPortKey        = "server_port"
	rpcGRPCStatusCodeKey = "rpc_grpc_status_code"
	rpcMethodKey         = "rpc_method"
	rpcSystemGRPC        = "rpc_system"
	DBOperationKey       = "db_operation"

	k8sNamespaceName   = "k8s_namespace_name"
	k8sPodName         = "k8s_pod_name"
	k8sDeploymentName  = "k8s_deployment_name"
	k8sStatefulSetName = "k8s_statefulset_name"
	k8sReplicaSetName  = "k8s_replicaset_name"
	k8sDaemonSetName   = "k8s_daemonset_name"
	k8sNodeName        = "k8s_node_name"
	k8sPodUID          = "k8s_pod_uid"
	k8sPodStartTime    = "k8s_pod_start_time"

	// default values for the histogram configuration
	// from https://grafana.com/docs/mimir/latest/send/native-histograms/#migrate-from-classic-histograms
	defaultHistogramBucketFactor     = 1.1
	defaultHistogramMaxBucketNumber  = uint32(100)
	defaultHistogramMinResetDuration = 1 * time.Hour
)

// metrics for Beyla statistics
const (
	BeylaBuildInfo = "beyla_build_info"

	LanguageLabel = "target_lang"
)

// not adding version, as it is a fixed value
var beylaInfoLabelNames = []string{LanguageLabel}

// TODO: TLS
type PrometheusConfig struct {
	Port           int    `yaml:"port" env:"BEYLA_PROMETHEUS_PORT"`
	Path           string `yaml:"path" env:"BEYLA_PROMETHEUS_PATH"`
	ReportTarget   bool   `yaml:"report_target" env:"BEYLA_METRICS_REPORT_TARGET"`
	ReportPeerInfo bool   `yaml:"report_peer" env:"BEYLA_METRICS_REPORT_PEER"`

	DisableBuildInfo bool `yaml:"disable_build_info" env:"BEYLA_PROMETHEUS_DISABLE_BUILD_INFO"`

	// Features of metrics that are can be exported. Accepted values are "application" and "network".
	Features []string `yaml:"features" env:"BEYLA_PROMETHEUS_FEATURES" envSeparator:","`

	Buckets otel.Buckets `yaml:"buckets"`

	// ExpireTime is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	ExpireTime time.Duration `yaml:"expire_time" env:"BEYLA_PROMETHEUS_EXPIRE_TIME"`

	// Registry is only used for embedding Beyla within the Grafana Agent.
	// It must be nil when Beyla runs as standalone
	Registry *prometheus.Registry `yaml:"-"`
}

// nolint:gocritic
func (p PrometheusConfig) Enabled() bool {
	return (p.Port != 0 || p.Registry != nil) && slices.Contains(p.Features, otel.FeatureApplication)
}

type metricsReporter struct {
	cfg *PrometheusConfig

	beylaInfo             *prometheus.GaugeVec
	httpDuration          *prometheus.HistogramVec
	httpClientDuration    *prometheus.HistogramVec
	grpcDuration          *prometheus.HistogramVec
	grpcClientDuration    *prometheus.HistogramVec
	sqlClientDuration     *prometheus.HistogramVec
	httpRequestSize       *prometheus.HistogramVec
	httpClientRequestSize *prometheus.HistogramVec

	promConnect *connector.PrometheusManager

	bgCtx   context.Context
	ctxInfo *global.ContextInfo
}

func PrometheusEndpoint(ctx context.Context, cfg *PrometheusConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]request.Span], error) {
	reporter := newReporter(ctx, cfg, ctxInfo)
	if cfg.Registry != nil {
		return reporter.collectMetrics, nil
	}
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
		beylaInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: BeylaBuildInfo,
			Help: "A metric with a constant '1' value labeled by version, revision, branch, " +
				"goversion from which Beyla was built, the goos and goarch for the build, and the" +
				"language of the reported services",
			ConstLabels: map[string]string{
				"goarch":    runtime.GOARCH,
				"goos":      runtime.GOOS,
				"goversion": runtime.Version(),
				"version":   buildinfo.Version,
				"revision":  buildinfo.Revision,
			},
		}, beylaInfoLabelNames),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            HTTPServerDuration,
			Help:                            "duration of HTTP service calls from the server side, in seconds",
			Buckets:                         cfg.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesHTTP(cfg, ctxInfo)),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            HTTPClientDuration,
			Help:                            "duration of HTTP service calls from the client side, in seconds",
			Buckets:                         cfg.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesHTTPClient(cfg, ctxInfo)),
		grpcDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            RPCServerDuration,
			Help:                            "duration of RCP service calls from the server side, in seconds",
			Buckets:                         cfg.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesGRPC(cfg, ctxInfo)),
		grpcClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            RPCClientDuration,
			Help:                            "duration of GRPC service calls from the client side, in seconds",
			Buckets:                         cfg.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesGRPCClient(cfg, ctxInfo)),
		sqlClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            SQLClientDuration,
			Help:                            "duration of SQL client operations, in seconds",
			Buckets:                         cfg.Buckets.DurationHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesSQL(ctxInfo)),
		httpRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            HTTPServerRequestSize,
			Help:                            "size, in bytes, of the HTTP request body as received at the server side",
			Buckets:                         cfg.Buckets.RequestSizeHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesHTTP(cfg, ctxInfo)),
		httpClientRequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:                            HTTPClientRequestSize,
			Help:                            "size, in bytes, of the HTTP request body as sent from the client side",
			Buckets:                         cfg.Buckets.RequestSizeHistogram,
			NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
			NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
			NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
		}, labelNamesHTTPClient(cfg, ctxInfo)),
	}

	var registeredMetrics []prometheus.Collector
	if !mr.cfg.DisableBuildInfo {
		registeredMetrics = append(registeredMetrics, mr.beylaInfo)
	}
	registeredMetrics = append(registeredMetrics,
		mr.httpClientRequestSize,
		mr.httpClientDuration,
		mr.grpcClientDuration,
		mr.sqlClientDuration,
		mr.httpRequestSize,
		mr.httpDuration,
		mr.grpcDuration)

	if mr.cfg.Registry != nil {
		mr.cfg.Registry.MustRegister(registeredMetrics...)
	} else {
		mr.promConnect.Register(cfg.Port, cfg.Path, registeredMetrics...)
	}

	return mr
}

func (r *metricsReporter) reportMetrics(input <-chan []request.Span) {
	go r.promConnect.StartHTTP(r.bgCtx)
	r.collectMetrics(input)
}

func (r *metricsReporter) collectMetrics(input <-chan []request.Span) {
	for spans := range input {
		for i := range spans {
			r.observe(&spans[i])
		}
	}
}

func (r *metricsReporter) observe(span *request.Span) {
	t := span.Timings()
	r.beylaInfo.WithLabelValues(span.ServiceID.SDKLanguage.String()).Set(1.0)
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
	case request.EventTypeSQLClient:
		r.sqlClientDuration.WithLabelValues(r.labelValuesSQL(span)...).Observe(duration)
	}
}

// labelNamesSQL must return the label names in the same order as would be returned
// by labelValuesSQL
func labelNamesSQL(ctxInfo *global.ContextInfo) []string {
	names := []string{targetInstanceKey, serviceNameKey, serviceNamespaceKey, DBOperationKey}
	if ctxInfo.K8sEnabled {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesSQL must return the label names in the same order as would be returned
// by labelNamesSQL
func (r *metricsReporter) labelValuesSQL(span *request.Span) []string {
	values := []string{span.ServiceID.Instance, span.ServiceID.Name, span.ServiceID.Namespace, span.Method}
	if r.ctxInfo.K8sEnabled {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

// labelNamesGRPC must return the label names in the same order as would be returned
// by labelValuesGRPC
func labelNamesGRPC(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	// TODO: let user configure which keys are going to be added
	names := []string{targetInstanceKey, serviceNameKey, serviceNamespaceKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, clientAddrKey)
	}
	if ctxInfo.K8sEnabled {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelNamesGRPCClient must return the label names in the same order as would be returned
// by labelValuesGRPC
func labelNamesGRPCClient(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	// TODO: let user configure which keys are going to be added
	names := []string{targetInstanceKey, serviceNameKey, serviceNamespaceKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, serverAddrKey)
	}
	if ctxInfo.K8sEnabled {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesGRPC
func (r *metricsReporter) labelValuesGRPC(span *request.Span) []string {
	// serviceNameKey, rpcMethodKey, rpcSystemGRPC, rpcGRPCStatusCodeKey
	values := []string{span.ServiceID.Instance, span.ServiceID.Name, span.ServiceID.Namespace, span.Path, "grpc", strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		values = append(values, span.Peer) // netSockPeerAddrKey
	}
	if r.ctxInfo.K8sEnabled {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

// labelNamesHTTPClient must return the label names in the same order as would be returned
// by labelValuesHTTPClient
func labelNamesHTTPClient(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	names := []string{targetInstanceKey, serviceNameKey, serviceNamespaceKey, httpMethodKey, httpStatusCodeKey}
	if cfg.ReportPeerInfo {
		names = append(names, serverAddrKey, serverPortKey)
	}
	if ctxInfo.K8sEnabled {
		names = appendK8sLabelNames(names)
	}
	if ctxInfo.AppO11y.ReportRoutes {
		names = append(names, httpRouteKey)
	}
	return names
}

// labelValuesHTTPClient must return the label names in the same order as would be returned
// by labelNamesHTTPClient
func (r *metricsReporter) labelValuesHTTPClient(span *request.Span) []string {
	// httpMethodKey, httpStatusCodeKey
	values := []string{span.ServiceID.Instance, span.ServiceID.Name, span.ServiceID.Namespace, span.Method, strconv.Itoa(span.Status)}
	if r.cfg.ReportPeerInfo {
		// netSockPeerAddrKey, netSockPeerPortKey
		values = append(values, span.Host, strconv.Itoa(span.HostPort))
	}
	if r.ctxInfo.K8sEnabled {
		values = appendK8sLabelValues(values, span)
	}
	if r.ctxInfo.AppO11y.ReportRoutes {
		values = append(values, span.Route) // httpRouteKey
	}
	return values
}

// labelNamesHTTP must return the label names in the same order as would be returned
// by labelValuesHTTP
func labelNamesHTTP(cfg *PrometheusConfig, ctxInfo *global.ContextInfo) []string {
	names := []string{targetInstanceKey, serviceNameKey, serviceNamespaceKey, httpMethodKey, httpStatusCodeKey}
	if cfg.ReportTarget {
		names = append(names, httpTargetKey)
	}
	if cfg.ReportPeerInfo {
		names = append(names, clientAddrKey)
	}
	if ctxInfo.AppO11y.ReportRoutes {
		names = append(names, httpRouteKey)
	}
	if ctxInfo.K8sEnabled {
		names = appendK8sLabelNames(names)
	}
	return names
}

// labelValuesGRPC must return the label names in the same order as would be returned
// by labelNamesHTTP
func (r *metricsReporter) labelValuesHTTP(span *request.Span) []string {
	// httpMethodKey, httpStatusCodeKey
	values := []string{span.ServiceID.Instance, span.ServiceID.Name, span.ServiceID.Namespace, span.Method, strconv.Itoa(span.Status)}
	if r.cfg.ReportTarget {
		values = append(values, span.Path) // httpTargetKey
	}
	if r.cfg.ReportPeerInfo {
		values = append(values, span.Peer) // netSockPeerAddrKey
	}
	if r.ctxInfo.AppO11y.ReportRoutes {
		values = append(values, span.Route) // httpRouteKey
	}
	if r.ctxInfo.K8sEnabled {
		values = appendK8sLabelValues(values, span)
	}
	return values
}

func appendK8sLabelNames(names []string) []string {
	names = append(names, k8sNamespaceName, k8sPodName, k8sNodeName, k8sPodUID, k8sPodStartTime,
		k8sDeploymentName, k8sReplicaSetName, k8sStatefulSetName, k8sDaemonSetName)
	return names
}

func appendK8sLabelValues(values []string, span *request.Span) []string {
	// must follow the order in appendK8sLabelNames
	values = append(values,
		span.ServiceID.Metadata[kube.NamespaceName],
		span.ServiceID.Metadata[kube.PodName],
		span.ServiceID.Metadata[kube.NodeName],
		span.ServiceID.Metadata[kube.PodUID],
		span.ServiceID.Metadata[kube.PodStartTime],
		span.ServiceID.Metadata[kube.DeploymentName],
		span.ServiceID.Metadata[kube.ReplicaSetName],
		span.ServiceID.Metadata[kube.StatefulSetName],
		span.ServiceID.Metadata[kube.DaemonSetName],
	)
	return values
}
