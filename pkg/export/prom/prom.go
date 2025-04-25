package prom

import (
	"context"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/v2/pkg/buildinfo"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/export/instrumentations"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

// injectable function reference for testing
var timeNow = time.Now

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	SpanMetricsLatency       = "traces_spanmetrics_latency"
	SpanMetricsCalls         = "traces_spanmetrics_calls_total"
	SpanMetricsRequestSizes  = "traces_spanmetrics_size_total"
	SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"
	TracesTargetInfo         = "traces_target_info"
	TracesHostInfo           = "traces_host_info"
	TargetInfo               = "target_info"

	ServiceGraphClient = "traces_service_graph_request_client_seconds"
	ServiceGraphServer = "traces_service_graph_request_server_seconds"
	ServiceGraphFailed = "traces_service_graph_request_failed_total"
	ServiceGraphTotal  = "traces_service_graph_request_total"

	serviceKey          = "service"
	serviceNamespaceKey = "service_namespace"

	hostIDKey        = "host_id"
	hostNameKey      = "host_name"
	grafanaHostIDKey = "grafana_host_id"
	processPIDKey    = "process_pid"
	osTypeKey        = "os_type"

	k8sNamespaceName   = "k8s_namespace_name"
	k8sPodName         = "k8s_pod_name"
	k8sContainerName   = "k8s_container_name"
	k8sDeploymentName  = "k8s_deployment_name"
	k8sStatefulSetName = "k8s_statefulset_name"
	k8sReplicaSetName  = "k8s_replicaset_name"
	k8sDaemonSetName   = "k8s_daemonset_name"
	k8sNodeName        = "k8s_node_name"
	k8sPodUID          = "k8s_pod_uid"
	k8sPodStartTime    = "k8s_pod_start_time"
	k8sClusterName     = "k8s_cluster_name"

	spanNameKey          = "span_name"
	statusCodeKey        = "status_code"
	spanKindKey          = "span_kind"
	serviceInstanceKey   = "instance"
	serviceJobKey        = "job"
	sourceKey            = "source"
	telemetryLanguageKey = "telemetry_sdk_language"
	telemetrySDKKey      = "telemetry_sdk_name"

	clientKey          = "client"
	clientNamespaceKey = "client_service_namespace"
	serverKey          = "server"
	serverNamespaceKey = "server_service_namespace"
	connectionTypeKey  = "connection_type"

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
var hostInfoLabelNames = []string{grafanaHostIDKey}

// TODO: TLS
type PrometheusConfig struct {
	Port int    `yaml:"port" env:"BEYLA_PROMETHEUS_PORT"`
	Path string `yaml:"path" env:"BEYLA_PROMETHEUS_PATH"`

	// nolint:undoc
	DisableBuildInfo bool `yaml:"disable_build_info" env:"BEYLA_PROMETHEUS_DISABLE_BUILD_INFO"`

	// Features of metrics that are can be exported. Accepted values are "application" and "network".
	Features []string `yaml:"features" env:"BEYLA_PROMETHEUS_FEATURES" envSeparator:","`
	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"BEYLA_PROMETHEUS_INSTRUMENTATIONS" envSeparator:","`

	Buckets otel.Buckets `yaml:"buckets"`

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL time.Duration `yaml:"ttl" env:"BEYLA_PROMETHEUS_TTL"`
	// nolint:undoc
	SpanMetricsServiceCacheSize int `yaml:"service_cache_size"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"BEYLA_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// Registry is only used for embedding Beyla within the Grafana Agent.
	// It must be nil when Beyla runs as standalone
	Registry *prometheus.Registry `yaml:"-"`

	// ExtraResourceLabels adds extra metadata labels to Prometheus metrics from sources whose availability can't be known
	// beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute,
	// you should add `deployment.environment`.
	ExtraResourceLabels []string `yaml:"extra_resource_attributes" env:"BEYLA_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES" envSeparator:","`
}

func (p *PrometheusConfig) SpanMetricsEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureSpan)
}

func (p *PrometheusConfig) OTelMetricsEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureApplication)
}

func (p *PrometheusConfig) ServiceGraphMetricsEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureGraph)
}

func (p *PrometheusConfig) NetworkMetricsEnabled() bool {
	return p.NetworkFlowBytesEnabled() || p.NetworkInterzoneMetricsEnabled()
}

func (p *PrometheusConfig) NetworkFlowBytesEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureNetwork)
}

func (p *PrometheusConfig) NetworkInterzoneMetricsEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureNetworkInterZone)
}

func (p *PrometheusConfig) EBPFEnabled() bool {
	return slices.Contains(p.Features, otel.FeatureEBPF)
}

func (p *PrometheusConfig) EndpointEnabled() bool {
	return p.Port != 0 || p.Registry != nil
}

// nolint:gocritic
func (p *PrometheusConfig) Enabled() bool {
	return p.EndpointEnabled() && (p.OTelMetricsEnabled() || p.SpanMetricsEnabled() || p.ServiceGraphMetricsEnabled() || p.NetworkMetricsEnabled())
}

type metricsReporter struct {
	cfg                 *PrometheusConfig
	extraMetadataLabels []attr.Name
	input               <-chan []request.Span

	beylaInfo              *Expirer[prometheus.Gauge]
	httpDuration           *Expirer[prometheus.Histogram]
	httpClientDuration     *Expirer[prometheus.Histogram]
	grpcDuration           *Expirer[prometheus.Histogram]
	grpcClientDuration     *Expirer[prometheus.Histogram]
	dbClientDuration       *Expirer[prometheus.Histogram]
	msgPublishDuration     *Expirer[prometheus.Histogram]
	msgProcessDuration     *Expirer[prometheus.Histogram]
	httpRequestSize        *Expirer[prometheus.Histogram]
	httpResponseSize       *Expirer[prometheus.Histogram]
	httpClientRequestSize  *Expirer[prometheus.Histogram]
	httpClientResponseSize *Expirer[prometheus.Histogram]
	targetInfo             *Expirer[prometheus.Gauge]

	// user-selected attributes for the application-level metrics
	attrHTTPDuration           []attributes.Field[*request.Span, string]
	attrHTTPClientDuration     []attributes.Field[*request.Span, string]
	attrGRPCDuration           []attributes.Field[*request.Span, string]
	attrGRPCClientDuration     []attributes.Field[*request.Span, string]
	attrDBClientDuration       []attributes.Field[*request.Span, string]
	attrMsgPublishDuration     []attributes.Field[*request.Span, string]
	attrMsgProcessDuration     []attributes.Field[*request.Span, string]
	attrHTTPRequestSize        []attributes.Field[*request.Span, string]
	attrHTTPResponseSize       []attributes.Field[*request.Span, string]
	attrHTTPClientRequestSize  []attributes.Field[*request.Span, string]
	attrHTTPClientResponseSize []attributes.Field[*request.Span, string]
	attrGPUKernelCalls         []attributes.Field[*request.Span, string]
	attrGPUMemoryAllocs        []attributes.Field[*request.Span, string]
	attrGPUKernelGridSize      []attributes.Field[*request.Span, string]
	attrGPUKernelBlockSize     []attributes.Field[*request.Span, string]

	// trace span metrics
	spanMetricsLatency           *Expirer[prometheus.Histogram]
	spanMetricsCallsTotal        *Expirer[prometheus.Counter]
	spanMetricsRequestSizeTotal  *Expirer[prometheus.Counter]
	spanMetricsResponseSizeTotal *Expirer[prometheus.Counter]
	tracesTargetInfo             *Expirer[prometheus.Gauge]
	tracesHostInfo               *Expirer[prometheus.Gauge]

	// trace service graph
	serviceGraphClient *Expirer[prometheus.Histogram]
	serviceGraphServer *Expirer[prometheus.Histogram]
	serviceGraphFailed *Expirer[prometheus.Counter]
	serviceGraphTotal  *Expirer[prometheus.Counter]

	// gpu related metrics
	gpuKernelCallsTotal  *Expirer[prometheus.Counter]
	gpuMemoryAllocsTotal *Expirer[prometheus.Counter]
	gpuKernelGridSize    *Expirer[prometheus.Histogram]
	gpuKernelBlockSize   *Expirer[prometheus.Histogram]

	promConnect *connector.PrometheusManager

	clock   *expire.CachedClock
	ctxInfo *global.ContextInfo

	is instrumentations.InstrumentationSelection

	kubeEnabled bool
	hostID      string

	serviceCache *expirable.LRU[svc.UID, svc.Attrs]
}

func PrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	attrSelect attributes.Selection,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		reporter, err := newReporter(ctxInfo, cfg, attrSelect, input)
		if err != nil {
			return nil, fmt.Errorf("instantiating Prometheus endpoint: %w", err)
		}
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

// nolint:cyclop
func newReporter(
	ctxInfo *global.ContextInfo, cfg *PrometheusConfig, selector attributes.Selection, input *msg.Queue[[]request.Span],
) (*metricsReporter, error) {
	groups := ctxInfo.MetricAttributeGroups
	groups.Add(attributes.GroupPrometheus)

	attrsProvider, err := attributes.NewAttrSelector(groups, selector)
	if err != nil {
		return nil, fmt.Errorf("selecting metrics attributes: %w", err)
	}

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	var attrHTTPDuration, attrHTTPClientDuration, attrHTTPRequestSize, attrHTTPResponseSize, attrHTTPClientRequestSize, attrHTTPClientResponseSize []attributes.Field[*request.Span, string]

	if is.HTTPEnabled() {
		attrHTTPDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPServerDuration))
		attrHTTPClientDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPClientDuration))
		attrHTTPRequestSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPServerRequestSize))
		attrHTTPResponseSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPServerResponseSize))
		attrHTTPClientRequestSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPClientRequestSize))
		attrHTTPClientResponseSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.HTTPClientResponseSize))
	}

	var attrGRPCDuration, attrGRPCClientDuration []attributes.Field[*request.Span, string]

	if is.GRPCEnabled() {
		attrGRPCDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.RPCServerDuration))
		attrGRPCClientDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.RPCClientDuration))
	}

	var attrDBClientDuration []attributes.Field[*request.Span, string]

	if is.DBEnabled() {
		attrDBClientDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.DBClientDuration))
	}

	var attrMessagingProcessDuration, attrMessagingPublishDuration []attributes.Field[*request.Span, string]

	if is.MQEnabled() {
		attrMessagingPublishDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.MessagingPublishDuration))
		attrMessagingProcessDuration = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.MessagingProcessDuration))
	}

	var attrGPUKernelLaunchCalls []attributes.Field[*request.Span, string]
	var attrGPUMemoryAllocations []attributes.Field[*request.Span, string]
	var attrGPUKernelGridSize []attributes.Field[*request.Span, string]
	var attrGPUKernelBlockSize []attributes.Field[*request.Span, string]

	if is.GPUEnabled() {
		attrGPUKernelLaunchCalls = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelLaunchCalls))
		attrGPUMemoryAllocations = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUMemoryAllocations))
		attrGPUKernelGridSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelGridSize))
		attrGPUKernelBlockSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelBlockSize))
	}

	clock := expire.NewCachedClock(timeNow)
	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)
	mr := &metricsReporter{
		input:                      input.Subscribe(),
		ctxInfo:                    ctxInfo,
		cfg:                        cfg,
		kubeEnabled:                kubeEnabled,
		extraMetadataLabels:        extraMetadataLabels,
		hostID:                     ctxInfo.HostID,
		clock:                      clock,
		is:                         is,
		promConnect:                ctxInfo.Prometheus,
		attrHTTPDuration:           attrHTTPDuration,
		attrHTTPClientDuration:     attrHTTPClientDuration,
		attrGRPCDuration:           attrGRPCDuration,
		attrGRPCClientDuration:     attrGRPCClientDuration,
		attrDBClientDuration:       attrDBClientDuration,
		attrMsgPublishDuration:     attrMessagingPublishDuration,
		attrMsgProcessDuration:     attrMessagingProcessDuration,
		attrHTTPRequestSize:        attrHTTPRequestSize,
		attrHTTPResponseSize:       attrHTTPResponseSize,
		attrHTTPClientRequestSize:  attrHTTPClientRequestSize,
		attrHTTPClientResponseSize: attrHTTPClientResponseSize,
		attrGPUKernelCalls:         attrGPUKernelLaunchCalls,
		attrGPUMemoryAllocs:        attrGPUMemoryAllocations,
		beylaInfo: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
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
		}, beylaInfoLabelNames).MetricVec, clock.Time, cfg.TTL),
		httpDuration: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerDuration.Prom,
				Help:                            "duration of HTTP service calls from the server side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		httpClientDuration: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientDuration.Prom,
				Help:                            "duration of HTTP service calls from the client side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPClientDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		grpcDuration: optionalHistogramProvider(is.GRPCEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.RPCServerDuration.Prom,
				Help:                            "duration of RCP service calls from the server side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrGRPCDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		grpcClientDuration: optionalHistogramProvider(is.GRPCEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.RPCClientDuration.Prom,
				Help:                            "duration of GRPC service calls from the client side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrGRPCClientDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		dbClientDuration: optionalHistogramProvider(is.DBEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.DBClientDuration.Prom,
				Help:                            "duration of db client operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrDBClientDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		msgPublishDuration: optionalHistogramProvider(is.MQEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.MessagingPublishDuration.Prom,
				Help:                            "duration of messaging client publish operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrMessagingPublishDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		msgProcessDuration: optionalHistogramProvider(is.MQEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.MessagingProcessDuration.Prom,
				Help:                            "duration of messaging client process operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrMessagingProcessDuration)).MetricVec, clock.Time, cfg.TTL)
		}),
		httpRequestSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerRequestSize.Prom,
				Help:                            "size, in bytes, of the HTTP request body as received at the server side",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPRequestSize)).MetricVec, clock.Time, cfg.TTL)
		}),
		httpResponseSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerResponseSize.Prom,
				Help:                            "size, in bytes, of the HTTP response body as received at the server side",
				Buckets:                         cfg.Buckets.ResponseSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPResponseSize)).MetricVec, clock.Time, cfg.TTL)
		}),
		httpClientRequestSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientRequestSize.Prom,
				Help:                            "size, in bytes, of the HTTP request body as sent from the client side",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPClientRequestSize)).MetricVec, clock.Time, cfg.TTL)
		}),
		httpClientResponseSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientResponseSize.Prom,
				Help:                            "size, in bytes, of the HTTP response body as sent from the client side",
				Buckets:                         cfg.Buckets.ResponseSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrHTTPClientResponseSize)).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsLatency: optionalHistogramProvider(cfg.SpanMetricsEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            SpanMetricsLatency,
				Help:                            "duration of service calls (client and server), in seconds, in trace span metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsCallsTotal: optionalCounterProvider(cfg.SpanMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsCalls,
				Help: "number of service calls in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsRequestSizeTotal: optionalCounterProvider(cfg.SpanMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsRequestSizes,
				Help: "size of service calls, in bytes, in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsResponseSizeTotal: optionalCounterProvider(cfg.SpanMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsResponseSizes,
				Help: "size of service responses, in bytes, in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		tracesTargetInfo: optionalGaugeProvider(cfg.SpanMetricsEnabled() || cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Gauge] {
			return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: TracesTargetInfo,
				Help: "target service information in trace span metric format",
			}, labelNamesTargetInfo(kubeEnabled, extraMetadataLabels)).MetricVec, clock.Time, cfg.TTL)
		}),
		tracesHostInfo: optionalGaugeProvider(cfg.SpanMetricsEnabled() || cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Gauge] {
			return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: TracesHostInfo,
				Help: "A metric with a constant '1' value labeled by the host id ",
			}, hostInfoLabelNames).MetricVec, clock.Time, cfg.TTL)
		}),
		serviceGraphClient: optionalHistogramProvider(cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            ServiceGraphClient,
				Help:                            "duration of client service calls, in seconds, in trace service graph metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNamesServiceGraph()).MetricVec, clock.Time, cfg.TTL)
		}),
		serviceGraphServer: optionalHistogramProvider(cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            ServiceGraphServer,
				Help:                            "duration of server service calls, in seconds, in trace service graph metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNamesServiceGraph()).MetricVec, clock.Time, cfg.TTL)
		}),
		serviceGraphFailed: optionalCounterProvider(cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ServiceGraphFailed,
				Help: "number of failed service calls in trace service graph metrics format",
			}, labelNamesServiceGraph()).MetricVec, clock.Time, cfg.TTL)
		}),
		serviceGraphTotal: optionalCounterProvider(cfg.ServiceGraphMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ServiceGraphTotal,
				Help: "number of service calls in trace service graph metrics format",
			}, labelNamesServiceGraph()).MetricVec, clock.Time, cfg.TTL)
		}),
		targetInfo: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: TargetInfo,
			Help: "attributes associated to a given monitored entity",
		}, labelNamesTargetInfo(kubeEnabled, extraMetadataLabels)).MetricVec, clock.Time, cfg.TTL),
		gpuKernelCallsTotal: optionalCounterProvider(is.GPUEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: attributes.GPUKernelLaunchCalls.Prom,
				Help: "number of GPU kernel launches",
			}, labelNames(attrGPUKernelLaunchCalls)).MetricVec, clock.Time, cfg.TTL)
		}),
		gpuMemoryAllocsTotal: optionalCounterProvider(is.GPUEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: attributes.GPUMemoryAllocations.Prom,
				Help: "amount of GPU allocated memory in bytes",
			}, labelNames(attrGPUMemoryAllocations)).MetricVec, clock.Time, cfg.TTL)
		}),
		gpuKernelGridSize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUKernelGridSize.Prom,
				Help:                            "number of blocks in the GPU kernel grid",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrGPUKernelGridSize)).MetricVec, clock.Time, cfg.TTL)
		}),
		gpuKernelBlockSize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUKernelBlockSize.Prom,
				Help:                            "number of threads in the GPU kernel block",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrGPUKernelBlockSize)).MetricVec, clock.Time, cfg.TTL)
		}),
	}

	if cfg.SpanMetricsEnabled() {
		mr.serviceCache = expirable.NewLRU(cfg.SpanMetricsServiceCacheSize, func(_ svc.UID, v svc.Attrs) {
			lv := mr.labelValuesTargetInfo(v)
			mr.tracesTargetInfo.WithLabelValues(lv...).metric.Set(0)
		}, cfg.TTL)
	}

	registeredMetrics := []prometheus.Collector{mr.targetInfo}

	if !mr.cfg.DisableBuildInfo {
		registeredMetrics = append(registeredMetrics, mr.beylaInfo)
	}

	if cfg.OTelMetricsEnabled() {
		if is.HTTPEnabled() {
			registeredMetrics = append(registeredMetrics,
				mr.httpClientRequestSize,
				mr.httpClientResponseSize,
				mr.httpClientDuration,
				mr.httpRequestSize,
				mr.httpResponseSize,
				mr.httpDuration,
			)
		}

		if is.GRPCEnabled() {
			registeredMetrics = append(registeredMetrics,
				mr.grpcClientDuration,
				mr.grpcDuration,
			)
		}

		if is.DBEnabled() {
			registeredMetrics = append(registeredMetrics,
				mr.dbClientDuration,
			)
		}

		if is.MQEnabled() {
			registeredMetrics = append(registeredMetrics,
				mr.msgProcessDuration,
				mr.msgPublishDuration,
			)
		}
	}

	if cfg.SpanMetricsEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.spanMetricsLatency,
			mr.spanMetricsCallsTotal,
			mr.spanMetricsRequestSizeTotal,
			mr.spanMetricsResponseSizeTotal,
			mr.tracesTargetInfo,
		)
	}

	if cfg.ServiceGraphMetricsEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.serviceGraphClient,
			mr.serviceGraphServer,
			mr.serviceGraphFailed,
			mr.serviceGraphTotal,
		)
	}

	if cfg.SpanMetricsEnabled() || cfg.ServiceGraphMetricsEnabled() {
		registeredMetrics = append(registeredMetrics, mr.tracesHostInfo)
	}

	if is.GPUEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.gpuKernelCallsTotal,
			mr.gpuMemoryAllocsTotal,
			mr.gpuKernelGridSize,
			mr.gpuKernelBlockSize,
		)
	}

	if mr.cfg.Registry != nil {
		mr.cfg.Registry.MustRegister(registeredMetrics...)
	} else {
		mr.promConnect.Register(cfg.Port, cfg.Path, registeredMetrics...)
	}

	return mr, nil
}

func parseExtraMetadata(labels []string) []attr.Name {
	// first, we convert any metric in snake_format to dotted.format,
	// as it is the internal representation of metadata labels
	attrNames := make([]attr.Name, len(labels))
	for i, label := range labels {
		attrNames[i] = attr.Name(strings.ReplaceAll(label, "_", "."))
	}
	return attrNames
}

func optionalHistogramProvider(enable bool, provider func() *Expirer[prometheus.Histogram]) *Expirer[prometheus.Histogram] {
	if !enable {
		return nil
	}

	return provider()
}

func optionalCounterProvider(enable bool, provider func() *Expirer[prometheus.Counter]) *Expirer[prometheus.Counter] {
	if !enable {
		return nil
	}

	return provider()
}

func optionalGaugeProvider(enable bool, provider func() *Expirer[prometheus.Gauge]) *Expirer[prometheus.Gauge] {
	if !enable {
		return nil
	}

	return provider()
}

func (r *metricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *metricsReporter) collectMetrics(_ context.Context) {
	for spans := range r.input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for i := range spans {
			r.observe(&spans[i])
		}
	}
}

func (r *metricsReporter) otelSpanObserved(span *request.Span) bool {
	return r.cfg.OTelMetricsEnabled() && !span.Service.ExportsOTelMetrics()
}

func (r *metricsReporter) otelSpanFiltered(span *request.Span) bool {
	return span.InternalSignal() || span.IgnoreMetrics()
}

// nolint:cyclop
func (r *metricsReporter) observe(span *request.Span) {
	if r.otelSpanFiltered(span) {
		return
	}
	t := span.Timings()
	r.beylaInfo.WithLabelValues(span.Service.SDKLanguage.String()).metric.Set(1.0)
	if r.cfg.SpanMetricsEnabled() || r.cfg.ServiceGraphMetricsEnabled() {
		r.tracesHostInfo.WithLabelValues(r.hostID).metric.Set(1.0)
	}
	duration := t.End.Sub(t.RequestStart).Seconds()

	targetInfoLabelValues := r.labelValuesTargetInfo(span.Service)
	r.targetInfo.WithLabelValues(targetInfoLabelValues...).metric.Set(1)

	if r.otelSpanObserved(span) {
		switch span.Type {
		case request.EventTypeHTTP:
			if r.is.HTTPEnabled() {
				r.httpDuration.WithLabelValues(
					labelValues(span, r.attrHTTPDuration)...,
				).metric.Observe(duration)
				r.httpRequestSize.WithLabelValues(
					labelValues(span, r.attrHTTPRequestSize)...,
				).metric.Observe(float64(span.RequestBodyLength()))
				r.httpResponseSize.WithLabelValues(
					labelValues(span, r.attrHTTPResponseSize)...,
				).metric.Observe(float64(span.ResponseBodyLength()))
			}
		case request.EventTypeHTTPClient:
			if r.is.HTTPEnabled() {
				r.httpClientDuration.WithLabelValues(
					labelValues(span, r.attrHTTPClientDuration)...,
				).metric.Observe(duration)
				r.httpClientRequestSize.WithLabelValues(
					labelValues(span, r.attrHTTPClientRequestSize)...,
				).metric.Observe(float64(span.RequestBodyLength()))
				r.httpClientResponseSize.WithLabelValues(
					labelValues(span, r.attrHTTPClientResponseSize)...,
				).metric.Observe(float64(span.ResponseBodyLength()))
			}
		case request.EventTypeGRPC:
			if r.is.GRPCEnabled() {
				r.grpcDuration.WithLabelValues(
					labelValues(span, r.attrGRPCDuration)...,
				).metric.Observe(duration)
			}
		case request.EventTypeGRPCClient:
			if r.is.GRPCEnabled() {
				r.grpcClientDuration.WithLabelValues(
					labelValues(span, r.attrGRPCClientDuration)...,
				).metric.Observe(duration)
			}
		case request.EventTypeRedisClient, request.EventTypeSQLClient, request.EventTypeRedisServer:
			if r.is.DBEnabled() {
				r.dbClientDuration.WithLabelValues(
					labelValues(span, r.attrDBClientDuration)...,
				).metric.Observe(duration)
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if r.is.MQEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					r.msgPublishDuration.WithLabelValues(
						labelValues(span, r.attrMsgPublishDuration)...,
					).metric.Observe(duration)
				case request.MessagingProcess:
					r.msgProcessDuration.WithLabelValues(
						labelValues(span, r.attrMsgProcessDuration)...,
					).metric.Observe(duration)
				}
			}
		case request.EventTypeGPUKernelLaunch:
			if r.is.GPUEnabled() {
				r.gpuKernelCallsTotal.WithLabelValues(
					labelValues(span, r.attrGPUKernelCalls)...,
				).metric.Add(1)
				r.gpuKernelGridSize.WithLabelValues(
					labelValues(span, r.attrGPUKernelGridSize)...,
				).metric.Observe(float64(span.ContentLength))
				r.gpuKernelBlockSize.WithLabelValues(
					labelValues(span, r.attrGPUKernelBlockSize)...,
				).metric.Observe(float64(span.SubType))
			}
		case request.EventTypeGPUMalloc:
			if r.is.GPUEnabled() {
				r.gpuMemoryAllocsTotal.WithLabelValues(
					labelValues(span, r.attrGPUMemoryAllocs)...,
				).metric.Add(float64(span.ContentLength))
			}
		}
	}

	if r.cfg.SpanMetricsEnabled() {
		lv := r.labelValuesSpans(span)
		r.spanMetricsLatency.WithLabelValues(lv...).metric.Observe(duration)
		r.spanMetricsCallsTotal.WithLabelValues(lv...).metric.Add(1)
		r.spanMetricsRequestSizeTotal.WithLabelValues(lv...).metric.Add(float64(span.RequestBodyLength()))
		r.spanMetricsResponseSizeTotal.WithLabelValues(lv...).metric.Add(float64(span.ResponseBodyLength()))

		_, ok := r.serviceCache.Get(span.Service.UID)
		if !ok {
			r.serviceCache.Add(span.Service.UID, span.Service)
			r.tracesTargetInfo.WithLabelValues(targetInfoLabelValues...).metric.Set(1)
		}
	}

	if r.cfg.ServiceGraphMetricsEnabled() {
		if !span.IsSelfReferenceSpan() || r.cfg.AllowServiceGraphSelfReferences {
			lvg := r.labelValuesServiceGraph(span)
			if span.IsClientSpan() {
				r.serviceGraphClient.WithLabelValues(lvg...).metric.Observe(duration)
			} else {
				r.serviceGraphServer.WithLabelValues(lvg...).metric.Observe(duration)
			}
			r.serviceGraphTotal.WithLabelValues(lvg...).metric.Add(1)
			if request.SpanStatusCode(span) == request.StatusCodeError {
				r.serviceGraphFailed.WithLabelValues(lvg...).metric.Add(1)
			}
		}
	}
}

func appendK8sLabelNames(names []string) []string {
	names = append(names, k8sNamespaceName, k8sPodName, k8sContainerName, k8sNodeName, k8sPodUID, k8sPodStartTime,
		k8sDeploymentName, k8sReplicaSetName, k8sStatefulSetName, k8sDaemonSetName, k8sClusterName)
	return names
}

func appendK8sLabelValuesService(values []string, service svc.Attrs) []string {
	// must follow the order in appendK8sLabelNames
	values = append(values,
		service.Metadata[(attr.K8sNamespaceName)],
		service.Metadata[(attr.K8sPodName)],
		service.Metadata[(attr.K8sContainerName)],
		service.Metadata[(attr.K8sNodeName)],
		service.Metadata[(attr.K8sPodUID)],
		service.Metadata[(attr.K8sPodStartTime)],
		service.Metadata[(attr.K8sDeploymentName)],
		service.Metadata[(attr.K8sReplicaSetName)],
		service.Metadata[(attr.K8sStatefulSetName)],
		service.Metadata[(attr.K8sDaemonSetName)],
		service.Metadata[(attr.K8sClusterName)],
	)
	return values
}

func labelNamesSpans() []string {
	return []string{serviceKey, serviceNamespaceKey, spanNameKey, statusCodeKey, spanKindKey, serviceInstanceKey, serviceJobKey, sourceKey}
}

func (r *metricsReporter) labelValuesSpans(span *request.Span) []string {
	return []string{
		span.Service.UID.Name,
		span.Service.UID.Namespace,
		span.TraceName(),
		request.SpanStatusCode(span),
		span.ServiceGraphKind(),
		span.Service.UID.Instance, // app instance ID
		span.Service.Job(),
		"beyla",
	}
}

func labelNamesTargetInfo(kubeEnabled bool, extraMetadataLabelNames []attr.Name) []string {
	names := []string{
		hostIDKey,
		hostNameKey,
		serviceKey,
		serviceNamespaceKey,
		serviceInstanceKey,
		serviceJobKey,
		telemetryLanguageKey,
		telemetrySDKKey,
		sourceKey,
		processPIDKey,
		osTypeKey,
	}

	if kubeEnabled {
		names = appendK8sLabelNames(names)
	}

	for _, mdn := range extraMetadataLabelNames {
		names = append(names, mdn.Prom())
	}

	return names
}

func (r *metricsReporter) labelValuesTargetInfo(service svc.Attrs) []string {
	values := []string{
		r.hostID,
		service.HostName,
		service.UID.Name,
		service.UID.Namespace,
		service.UID.Instance, // app instance ID
		service.Job(),
		service.SDKLanguage.String(),
		"beyla",
		"beyla",
		strconv.Itoa(int(service.ProcPID)),
		"linux",
	}

	if r.kubeEnabled {
		values = appendK8sLabelValuesService(values, service)
	}

	for _, k := range r.extraMetadataLabels {
		values = append(values, service.Metadata[k])
	}

	return values
}

func labelNamesServiceGraph() []string {
	return []string{clientKey, clientNamespaceKey, serverKey, serverNamespaceKey, sourceKey}
}

func (r *metricsReporter) labelValuesServiceGraph(span *request.Span) []string {
	if span.IsClientSpan() {
		return []string{
			request.SpanPeer(span),
			span.Service.UID.Namespace,
			request.SpanHost(span),
			span.OtherNamespace,
			"beyla",
		}
	}
	return []string{
		request.SpanPeer(span),
		span.OtherNamespace,
		request.SpanHost(span),
		span.Service.UID.Namespace,
		"beyla",
	}
}

func labelNames[T any](getters []attributes.Field[T, string]) []string {
	labels := make([]string, 0, len(getters))
	for _, label := range getters {
		labels = append(labels, label.ExposedName)
	}
	return labels
}

func labelValues[T any](s T, getters []attributes.Field[T, string]) []string {
	values := make([]string, 0, len(getters))
	for _, getter := range getters {
		values = append(values, getter.Get(s))
	}
	return values
}
