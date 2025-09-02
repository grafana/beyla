// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// injectable function reference for testing
var timeNow = time.Now

// using labels and names that are equivalent names to the OTEL attributes
// but following the different naming conventions
const (
	SpanMetricsLatency       = "traces_spanmetrics_latency"
	SpanMetricsLatencyOTel   = "traces_span_metrics_duration_seconds"
	SpanMetricsCalls         = "traces_spanmetrics_calls_total"
	SpanMetricsCallsOTel     = "traces_span_metrics_calls_total"
	SpanMetricsRequestSizes  = "traces_spanmetrics_size_total"
	SpanMetricsResponseSizes = "traces_spanmetrics_response_size_total"
	TracesTargetInfo         = "traces_target_info"
	TracesHostInfo           = "traces_host_info"
	TargetInfo               = "target_info"

	ServiceGraphClient = "traces_service_graph_request_client_seconds"
	ServiceGraphServer = "traces_service_graph_request_server_seconds"
	ServiceGraphFailed = "traces_service_graph_request_failed_total"
	ServiceGraphTotal  = "traces_service_graph_request_total"

	serviceNameKey      = "service_name"
	serviceNamespaceKey = "service_namespace"

	hostIDKey        = "host_id"
	hostNameKey      = "host_name"
	grafanaHostIDKey = "grafana_host_id"
	osTypeKey        = "os_type"

	k8sNamespaceName   = "k8s_namespace_name"
	k8sPodName         = "k8s_pod_name"
	k8sContainerName   = "k8s_container_name"
	k8sDeploymentName  = "k8s_deployment_name"
	k8sStatefulSetName = "k8s_statefulset_name"
	k8sReplicaSetName  = "k8s_replicaset_name"
	k8sDaemonSetName   = "k8s_daemonset_name"
	k8sJobName         = "k8s_job_name"
	k8sCronJobName     = "k8s_cronjob_name"
	k8sNodeName        = "k8s_node_name"
	k8sPodUID          = "k8s_pod_uid"
	k8sPodStartTime    = "k8s_pod_start_time"
	k8sClusterName     = "k8s_cluster_name"
	k8sKind            = "k8s_kind"
	k8sOwnerName       = "k8s_owner_name"

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
	buildInfoSuffix = "_build_info"

	LanguageLabel = "target_lang"
)

// not adding version, as it is a fixed value
var (
	beylaInfoLabelNames = []string{LanguageLabel}
	hostInfoLabelNames  = []string{grafanaHostIDKey}
)

// TODO: TLS
type PrometheusConfig struct {
	Port int    `yaml:"port" env:"OTEL_EBPF_PROMETHEUS_PORT"`
	Path string `yaml:"path" env:"OTEL_EBPF_PROMETHEUS_PATH"`

	DisableBuildInfo bool `yaml:"disable_build_info" env:"OTEL_EBPF_PROMETHEUS_DISABLE_BUILD_INFO"`

	// Features of metrics that are can be exported. Accepted values are "application" and "network".
	Features []string `yaml:"features" env:"OTEL_EBPF_PROMETHEUS_FEATURES" envSeparator:","`
	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS" envSeparator:","`

	Buckets otelcfg.Buckets `yaml:"buckets"`

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL                         time.Duration `yaml:"ttl" env:"OTEL_EBPF_PROMETHEUS_TTL"`
	SpanMetricsServiceCacheSize int           `yaml:"service_cache_size"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"OTEL_EBPF_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// Registry is only used for embedding Beyla within the Grafana Agent.
	// It must be nil when Beyla runs as standalone
	Registry *prometheus.Registry `yaml:"-"`

	// ExtraResourceLabels adds extra metadata labels to Prometheus metrics from sources whose availability can't be known
	// beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute,
	// you should add `deployment.environment`.
	ExtraResourceLabels []string `yaml:"extra_resource_attributes" env:"OTEL_EBPF_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES" envSeparator:","`
}

func mlog() *slog.Logger {
	return slog.With("component", "prom.MetricsReporter")
}

func (p *PrometheusConfig) AnySpanMetricsEnabled() bool {
	return p.SpanMetricsEnabled() || p.SpanMetricsSizesEnabled() || p.ServiceGraphMetricsEnabled()
}

func (p *PrometheusConfig) SpanMetricsSizesEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureSpanSizes)
}

func (p *PrometheusConfig) SpanMetricsEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureSpan) || slices.Contains(p.Features, otelcfg.FeatureSpanOTel)
}

func (p *PrometheusConfig) InvalidSpanMetricsConfig() bool {
	return slices.Contains(p.Features, otelcfg.FeatureSpan) && slices.Contains(p.Features, otelcfg.FeatureSpanOTel)
}

func (p *PrometheusConfig) HostMetricsEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureApplicationHost)
}

func (p *PrometheusConfig) OTelMetricsEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureApplication)
}

func (p *PrometheusConfig) ServiceGraphMetricsEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureGraph)
}

func (p *PrometheusConfig) NetworkMetricsEnabled() bool {
	return p.NetworkFlowBytesEnabled() || p.NetworkInterzoneMetricsEnabled()
}

func (p *PrometheusConfig) NetworkFlowBytesEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureNetwork)
}

func (p *PrometheusConfig) NetworkInterzoneMetricsEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureNetworkInterZone)
}

func (p *PrometheusConfig) EBPFEnabled() bool {
	return slices.Contains(p.Features, otelcfg.FeatureEBPF)
}

func (p *PrometheusConfig) EndpointEnabled() bool {
	return p.Port != 0 || p.Registry != nil
}

// Enabled returns whether the node needs to be activated
func (p *PrometheusConfig) Enabled() bool {
	return p.EndpointEnabled() && (p.OTelMetricsEnabled() || p.AnySpanMetricsEnabled() || p.NetworkMetricsEnabled())
}

type metricsReporter struct {
	cfg                 *PrometheusConfig
	extraMetadataLabels []attr.Name
	input               <-chan []request.Span
	processEvents       <-chan exec.ProcessEvent

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
	targetInfo             *prometheus.GaugeVec

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
	attrGPUMemoryCopies        []attributes.Field[*request.Span, string]

	// trace span metrics
	spanMetricsLatency           *Expirer[prometheus.Histogram]
	spanMetricsCallsTotal        *Expirer[prometheus.Counter]
	spanMetricsRequestSizeTotal  *Expirer[prometheus.Counter]
	spanMetricsResponseSizeTotal *Expirer[prometheus.Counter]
	tracesHostInfo               *Expirer[prometheus.Gauge]
	tracesTargetInfo             *prometheus.GaugeVec

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
	gpuMemoryCopySize    *Expirer[prometheus.Histogram]

	promConnect *connector.PrometheusManager

	clock   *expire.CachedClock
	ctxInfo *global.ContextInfo

	is instrumentations.InstrumentationSelection

	kubeEnabled bool
	hostID      string

	serviceMap  map[svc.UID]svc.Attrs
	pidsTracker otel.PidServiceTracker
}

func PrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		reporter, err := newReporter(ctxInfo, cfg, selectorCfg, input, processEventCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating Prometheus endpoint: %w", err)
		}
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func (p *PrometheusConfig) spanMetricsLatencyName() string {
	if slices.Contains(p.Features, otelcfg.FeatureSpan) {
		return SpanMetricsLatency
	}

	return SpanMetricsLatencyOTel
}

func (p *PrometheusConfig) spanMetricsCallsName() string {
	if slices.Contains(p.Features, otelcfg.FeatureSpan) {
		return SpanMetricsCalls
	}

	return SpanMetricsCallsOTel
}

//nolint:cyclop
func newReporter(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
) (*metricsReporter, error) {
	groups := ctxInfo.MetricAttributeGroups
	groups.Add(attributes.GroupPrometheus)

	attrsProvider, err := attributes.NewAttrSelector(groups, selectorCfg)
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
	var attrGPUMemoryCopies []attributes.Field[*request.Span, string]

	if is.GPUEnabled() {
		attrGPUKernelLaunchCalls = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelLaunchCalls))
		attrGPUMemoryAllocations = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUMemoryAllocations))
		attrGPUKernelGridSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelGridSize))
		attrGPUKernelBlockSize = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUKernelBlockSize))
		attrGPUMemoryCopies = attributes.PrometheusGetters(request.SpanPromGetters,
			attrsProvider.For(attributes.GPUMemoryCopies))
	}

	clock := expire.NewCachedClock(timeNow)
	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)
	mr := &metricsReporter{
		input:                      input.Subscribe(),
		processEvents:              processEventCh.Subscribe(),
		serviceMap:                 map[svc.UID]svc.Attrs{},
		pidsTracker:                otel.NewPidServiceTracker(),
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
		attrGPUKernelGridSize:      attrGPUKernelGridSize,
		attrGPUKernelBlockSize:     attrGPUKernelBlockSize,
		attrGPUMemoryCopies:        attrGPUMemoryCopies,
		beylaInfo: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + buildInfoSuffix,
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
				Name:                            cfg.spanMetricsLatencyName(),
				Help:                            "duration of service calls (client and server), in seconds, in trace span metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsCallsTotal: optionalCounterProvider(cfg.SpanMetricsEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: cfg.spanMetricsCallsName(),
				Help: "number of service calls in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsRequestSizeTotal: optionalCounterProvider(cfg.SpanMetricsSizesEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsRequestSizes,
				Help: "size of service calls, in bytes, in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		spanMetricsResponseSizeTotal: optionalCounterProvider(cfg.SpanMetricsSizesEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsResponseSizes,
				Help: "size of service responses, in bytes, in trace span metrics format",
			}, labelNamesSpans()).MetricVec, clock.Time, cfg.TTL)
		}),
		tracesTargetInfo: optionalDirectGaugeProvider(cfg.AnySpanMetricsEnabled(), func() *prometheus.GaugeVec {
			return prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: TracesTargetInfo,
				Help: "target service information in trace span metric format",
			}, labelNamesTargetInfo(kubeEnabled, extraMetadataLabels))
		}),
		tracesHostInfo: optionalGaugeProvider(cfg.HostMetricsEnabled(), func() *Expirer[prometheus.Gauge] {
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
		targetInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: TargetInfo,
			Help: "attributes associated to a given monitored entity",
		}, labelNamesTargetInfo(kubeEnabled, extraMetadataLabels)),
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
		gpuMemoryCopySize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUMemoryCopies.Prom,
				Help:                            "amount of GPU to and from memory copies",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     defaultHistogramBucketFactor,
				NativeHistogramMaxBucketNumber:  defaultHistogramMaxBucketNumber,
				NativeHistogramMinResetDuration: defaultHistogramMinResetDuration,
			}, labelNames(attrGPUMemoryCopies)).MetricVec, clock.Time, cfg.TTL)
		}),
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
		)
	}

	if cfg.SpanMetricsSizesEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.spanMetricsRequestSizeTotal,
			mr.spanMetricsResponseSizeTotal,
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

	if cfg.AnySpanMetricsEnabled() {
		registeredMetrics = append(registeredMetrics, mr.tracesTargetInfo)
	}

	if cfg.HostMetricsEnabled() {
		registeredMetrics = append(registeredMetrics, mr.tracesHostInfo)
	}

	if is.GPUEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.gpuKernelCallsTotal,
			mr.gpuMemoryAllocsTotal,
			mr.gpuKernelGridSize,
			mr.gpuKernelBlockSize,
			mr.gpuMemoryCopySize,
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

func optionalDirectGaugeProvider(enable bool, provider func() *prometheus.GaugeVec) *prometheus.GaugeVec {
	if !enable {
		return nil
	}

	return provider()
}

func (r *metricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *metricsReporter) collectMetrics(ctx context.Context) {
	go r.watchForProcessEvents(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case spans, ok := <-r.input:
			if !ok {
				return
			}
			// clock needs to be updated to let the expirer
			// remove the old metrics
			r.clock.Update()
			for i := range spans {
				r.observe(&spans[i])
			}
		}
	}
}

func (r *metricsReporter) otelMetricsObserved(span *request.Span) bool {
	return r.cfg.OTelMetricsEnabled() && !span.Service.ExportsOTelMetrics()
}

func (r *metricsReporter) otelSpanMetricsObserved(span *request.Span) bool {
	return r.cfg.AnySpanMetricsEnabled() && !span.Service.ExportsOTelMetricsSpan()
}

func (r *metricsReporter) otelSpanFiltered(span *request.Span) bool {
	return span.InternalSignal() || request.IgnoreMetrics(span)
}

//nolint:cyclop
func (r *metricsReporter) observe(span *request.Span) {
	if r.otelSpanFiltered(span) {
		return
	}
	if !span.Service.ExportModes.CanExportMetrics() {
		return
	}
	t := span.Timings()
	r.beylaInfo.WithLabelValues(span.Service.SDKLanguage.String()).Metric.Set(1.0)
	if r.cfg.HostMetricsEnabled() {
		r.tracesHostInfo.WithLabelValues(r.hostID).Metric.Set(1.0)
	}
	duration := t.End.Sub(t.RequestStart).Seconds()

	if r.otelMetricsObserved(span) {
		switch span.Type {
		case request.EventTypeHTTP:
			if r.is.HTTPEnabled() {
				r.httpDuration.WithLabelValues(
					labelValues(span, r.attrHTTPDuration)...,
				).Metric.Observe(duration)
				r.httpRequestSize.WithLabelValues(
					labelValues(span, r.attrHTTPRequestSize)...,
				).Metric.Observe(float64(span.RequestBodyLength()))
				r.httpResponseSize.WithLabelValues(
					labelValues(span, r.attrHTTPResponseSize)...,
				).Metric.Observe(float64(span.ResponseBodyLength()))
			}
		case request.EventTypeHTTPClient:
			if r.is.HTTPEnabled() {
				r.httpClientDuration.WithLabelValues(
					labelValues(span, r.attrHTTPClientDuration)...,
				).Metric.Observe(duration)
				r.httpClientRequestSize.WithLabelValues(
					labelValues(span, r.attrHTTPClientRequestSize)...,
				).Metric.Observe(float64(span.RequestBodyLength()))
				r.httpClientResponseSize.WithLabelValues(
					labelValues(span, r.attrHTTPClientResponseSize)...,
				).Metric.Observe(float64(span.ResponseBodyLength()))
			}
		case request.EventTypeGRPC:
			if r.is.GRPCEnabled() {
				r.grpcDuration.WithLabelValues(
					labelValues(span, r.attrGRPCDuration)...,
				).Metric.Observe(duration)
			}
		case request.EventTypeGRPCClient:
			if r.is.GRPCEnabled() {
				r.grpcClientDuration.WithLabelValues(
					labelValues(span, r.attrGRPCClientDuration)...,
				).Metric.Observe(duration)
			}
		case request.EventTypeRedisClient, request.EventTypeSQLClient, request.EventTypeRedisServer, request.EventTypeMongoClient:
			if r.is.DBEnabled() {
				r.dbClientDuration.WithLabelValues(
					labelValues(span, r.attrDBClientDuration)...,
				).Metric.Observe(duration)
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if r.is.MQEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					r.msgPublishDuration.WithLabelValues(
						labelValues(span, r.attrMsgPublishDuration)...,
					).Metric.Observe(duration)
				case request.MessagingProcess:
					r.msgProcessDuration.WithLabelValues(
						labelValues(span, r.attrMsgProcessDuration)...,
					).Metric.Observe(duration)
				}
			}
		case request.EventTypeGPUKernelLaunch:
			if r.is.GPUEnabled() {
				r.gpuKernelCallsTotal.WithLabelValues(
					labelValues(span, r.attrGPUKernelCalls)...,
				).Metric.Add(1)
				r.gpuKernelGridSize.WithLabelValues(
					labelValues(span, r.attrGPUKernelGridSize)...,
				).Metric.Observe(float64(span.ContentLength))
				r.gpuKernelBlockSize.WithLabelValues(
					labelValues(span, r.attrGPUKernelBlockSize)...,
				).Metric.Observe(float64(span.SubType))
			}
		case request.EventTypeGPUMalloc:
			if r.is.GPUEnabled() {
				r.gpuMemoryAllocsTotal.WithLabelValues(
					labelValues(span, r.attrGPUMemoryAllocs)...,
				).Metric.Add(float64(span.ContentLength))
			}
		case request.EventTypeGPUMemcpy:
			if r.is.GPUEnabled() {
				r.gpuMemoryCopySize.WithLabelValues(
					labelValues(span, r.attrGPUMemoryCopies)...,
				).Metric.Observe(float64(span.ContentLength))
			}
		}
	}

	if r.otelSpanMetricsObserved(span) {
		if r.cfg.SpanMetricsEnabled() {
			lv := r.labelValuesSpans(span)
			r.spanMetricsLatency.WithLabelValues(lv...).Metric.Observe(duration)
			r.spanMetricsCallsTotal.WithLabelValues(lv...).Metric.Add(1)
		}

		if r.cfg.SpanMetricsSizesEnabled() {
			lv := r.labelValuesSpans(span)
			r.spanMetricsRequestSizeTotal.WithLabelValues(lv...).Metric.Add(float64(span.RequestBodyLength()))
			r.spanMetricsResponseSizeTotal.WithLabelValues(lv...).Metric.Add(float64(span.ResponseBodyLength()))
		}

		if r.cfg.ServiceGraphMetricsEnabled() {
			if !span.IsSelfReferenceSpan() || r.cfg.AllowServiceGraphSelfReferences {
				lvg := r.labelValuesServiceGraph(span)

				if span.IsClientSpan() {
					r.serviceGraphClient.WithLabelValues(lvg...).Metric.Observe(duration)
					// If we managed to resolve the remote name only, we check to see
					// we are not instrumenting the server service, then and only then,
					// we generate client span count for service graph total
					if otel.ClientSpanToUninstrumentedService(&r.pidsTracker, span) {
						r.serviceGraphTotal.WithLabelValues(lvg...).Metric.Add(1)
					}
				} else {
					r.serviceGraphServer.WithLabelValues(lvg...).Metric.Observe(duration)
					r.serviceGraphTotal.WithLabelValues(lvg...).Metric.Add(1)
				}
				if request.SpanStatusCode(span) == request.StatusCodeError {
					r.serviceGraphFailed.WithLabelValues(lvg...).Metric.Add(1)
				}
			}
		}
	}
}

func appendK8sLabelNames(names []string) []string {
	names = append(names, k8sNamespaceName, k8sPodName, k8sContainerName, k8sNodeName, k8sPodUID, k8sPodStartTime,
		k8sDeploymentName, k8sReplicaSetName, k8sStatefulSetName, k8sJobName, k8sCronJobName, k8sDaemonSetName, k8sClusterName, k8sKind, k8sOwnerName)
	return names
}

func appendK8sLabelValuesService(values []string, service *svc.Attrs) []string {
	// must follow the order in appendK8sLabelNames
	values = append(values,
		service.Metadata[attr.K8sNamespaceName],
		service.Metadata[attr.K8sPodName],
		service.Metadata[attr.K8sContainerName],
		service.Metadata[attr.K8sNodeName],
		service.Metadata[attr.K8sPodUID],
		service.Metadata[attr.K8sPodStartTime],
		service.Metadata[attr.K8sDeploymentName],
		service.Metadata[attr.K8sReplicaSetName],
		service.Metadata[attr.K8sStatefulSetName],
		service.Metadata[attr.K8sJobName],
		service.Metadata[attr.K8sCronJobName],
		service.Metadata[attr.K8sDaemonSetName],
		service.Metadata[attr.K8sClusterName],
		service.Metadata[attr.K8sKind],
		service.Metadata[attr.K8sOwnerName],
	)
	return values
}

func labelNamesSpans() []string {
	return []string{serviceNameKey, serviceNamespaceKey, spanNameKey, statusCodeKey, spanKindKey, serviceInstanceKey, serviceJobKey, sourceKey}
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
		attr.VendorPrefix,
	}
}

func labelNamesTargetInfo(kubeEnabled bool, extraMetadataLabelNames []attr.Name) []string {
	names := []string{
		hostIDKey,
		hostNameKey,
		serviceNameKey,
		serviceNamespaceKey,
		serviceInstanceKey,
		serviceJobKey,
		telemetryLanguageKey,
		telemetrySDKKey,
		sourceKey,
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

func (r *metricsReporter) labelValuesTargetInfo(service *svc.Attrs) []string {
	values := []string{
		r.hostID,
		service.HostName,
		service.UID.Name,
		service.UID.Namespace,
		service.UID.Instance, // app instance ID
		service.Job(),
		service.SDKLanguage.String(),
		attr.VendorPrefix,
		attr.VendorPrefix,
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
			attr.VendorPrefix,
		}
	}
	return []string{
		request.SpanPeer(span),
		span.OtherNamespace,
		request.SpanHost(span),
		span.Service.UID.Namespace,
		attr.VendorPrefix,
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
		rawValue := getter.Get(s)
		sanitizedValue := sanitizeUTF8ForPrometheus(rawValue)
		values = append(values, sanitizedValue)
	}
	return values
}

// sanitizeUTF8ForPrometheus sanitizes a string to ensure it contains only valid UTF-8 characters.
// Invalid UTF-8 sequences are removed entirely.
func sanitizeUTF8ForPrometheus(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "")
}

func (r *metricsReporter) createTargetInfo(service *svc.Attrs) {
	targetInfoLabelValues := r.labelValuesTargetInfo(service)
	r.targetInfo.WithLabelValues(targetInfoLabelValues...).Set(1)
}

func (r *metricsReporter) createTracesTargetInfo(service *svc.Attrs) {
	if !r.cfg.AnySpanMetricsEnabled() {
		return
	}
	targetInfoLabelValues := r.labelValuesTargetInfo(service)
	r.tracesTargetInfo.WithLabelValues(targetInfoLabelValues...).Set(1)
}

func (r *metricsReporter) origService(uid svc.UID, service *svc.Attrs) *svc.Attrs {
	orig := service
	if origAttrs, ok := r.serviceMap[uid]; ok {
		orig = &origAttrs
	}
	return orig
}

func (r *metricsReporter) deleteTargetInfo(uid svc.UID, service *svc.Attrs) {
	targetInfoLabelValues := r.labelValuesTargetInfo(r.origService(uid, service))
	r.targetInfo.DeleteLabelValues(targetInfoLabelValues...)
}

func (r *metricsReporter) deleteTracesTargetInfo(uid svc.UID, service *svc.Attrs) {
	if !r.cfg.AnySpanMetricsEnabled() {
		return
	}
	targetInfoLabelValues := r.labelValuesTargetInfo(r.origService(uid, service))
	r.tracesTargetInfo.DeleteLabelValues(targetInfoLabelValues...)
}

func (r *metricsReporter) setupPIDToServiceRelationship(pid int32, uid svc.UID) {
	r.pidsTracker.AddPID(pid, uid)
}

func (r *metricsReporter) disassociatePIDFromService(pid int32) (bool, svc.UID) {
	return r.pidsTracker.RemovePID(pid)
}

func (r *metricsReporter) watchForProcessEvents(ctx context.Context) {
	log := mlog().With("function", "watchForProcessEvents")
	for {
		select {
		case pe, ok := <-r.processEvents:
			if !ok {
				log.Debug("process channel closed. Exiting")
				return
			}
			log.Debug("Received new process event", "event type", pe.Type, "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
			uid := pe.File.Service.UID

			if pe.Type == exec.ProcessEventCreated {
				r.createTargetInfo(&pe.File.Service)
				r.createTracesTargetInfo(&pe.File.Service)
				r.serviceMap[uid] = pe.File.Service
				r.setupPIDToServiceRelationship(pe.File.Pid, uid)
			} else {
				if deleted, origUID := r.disassociatePIDFromService(pe.File.Pid); deleted {
					mlog().Debug("deleting infos for", "pid", pe.File.Pid, "attrs", pe.File.Service.UID)
					r.deleteTargetInfo(origUID, &pe.File.Service)
					r.deleteTracesTargetInfo(origUID, &pe.File.Service)
					if r.cfg.HostMetricsEnabled() && r.pidsTracker.Count() == 0 {
						mlog().Debug("No more PIDs tracked, expiring host info metric")
						r.tracesHostInfo.entries.DeleteAll()
					}
					delete(r.serviceMap, origUID)
				}
			}
		case <-ctx.Done():
			log.Debug("Context done. Exiting")
			return
		}
	}
}
