// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// injectable function reference for testing
var timeNow = time.Now

// CloudHostIDKey is the attribute key used to label metrics with the host id
// of the monitored entity, as reported by the executable inspector. It is used
// for both application-level and trace-level metrics.
var CloudHostIDKey = "cloud_host_id"

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

	spanNameKey          = "span_name"
	statusCodeKey        = "status_code"
	spanKindKey          = "span_kind"
	serviceInstanceKey   = "instance"
	serviceJobKey        = "job"
	sourceKey            = "source"
	telemetryLanguageKey = "telemetry_sdk_language"
)

// metrics for OBI statistics
const (
	buildInfoSuffix = "_build_info"

	LanguageLabel = "target_lang"
)

// not adding version, as it is a fixed value
var (
	obiInfoLabelNames = []string{LanguageLabel}
)

// NativeHistogramConfig holds configuration for native histograms
type NativeHistogramConfig struct {
	BucketFactor     float64       `yaml:"bucket_factor" env:"OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_BUCKET_FACTOR" validate:"gt=1"`
	MaxBucketNumber  uint32        `yaml:"max_bucket_number" env:"OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_MAX_BUCKET_NUMBER" validate:"gt=0"`
	MinResetDuration time.Duration `yaml:"min_reset_duration" env:"OTEL_EBPF_PROMETHEUS_NATIVE_HISTOGRAM_MIN_RESET_DURATION" validate:"gt=0"`
}

var DefaultNativeHistogramConfig = NativeHistogramConfig{
	// recommended values for native histogram migration
	BucketFactor:     1.1,
	MaxBucketNumber:  100,
	MinResetDuration: time.Hour,
}

// TODO: TLS
type PrometheusConfig struct {
	// 0 means disabled
	Port int    `yaml:"port" env:"OTEL_EBPF_PROMETHEUS_PORT" validate:"gte=0,lte=65535"`
	Path string `yaml:"path" env:"OTEL_EBPF_PROMETHEUS_PATH"`

	DisableBuildInfo bool `yaml:"disable_build_info" env:"OTEL_EBPF_PROMETHEUS_DISABLE_BUILD_INFO"`

	// Features specifies which metric features to export. Accepted values: application, network,
	// application_span, application_service_graph, ...
	//
	// Deprecated: use top-level MetricsConfig.Features instead.
	DeprFeatures export.Features `yaml:"features" env:"OTEL_EBPF_PROMETHEUS_FEATURES" envSeparator:","`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []instrumentations.Instrumentation `yaml:"instrumentations" env:"OTEL_EBPF_PROMETHEUS_INSTRUMENTATIONS" envSeparator:","`

	Buckets export.Buckets `yaml:"buckets"`

	// TTL specifies the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL                         time.Duration `yaml:"ttl" env:"OTEL_EBPF_PROMETHEUS_TTL"`
	SpanMetricsServiceCacheSize int           `yaml:"service_cache_size" validate:"gt=0"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"OTEL_EBPF_PROMETHEUS_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// ExemplarFilter controls when exemplars are attached to metrics.
	// Accepted values: "always_on", "always_off", "trace_based".
	// Defaults to "always_off": do not attach exemplars.
	// This mimics the OTEL_METRICS_EXEMPLAR_FILTER specification.
	ExemplarFilter string `yaml:"exemplar_filter" env:"OTEL_EBPF_PROMETHEUS_EXEMPLAR_FILTER"`

	// NativeHistogram configures native histogram bucket parameters.
	// Uses recommended values if not specified.
	NativeHistogram NativeHistogramConfig `yaml:"native_histogram"`

	// Registry is only used for embedding OBI within third-party collectors.
	// It must be nil when OBI runs as standalone
	Registry *prometheus.Registry `yaml:"-"`

	// ExtraResourceLabels adds extra metadata labels to Prometheus metrics from sources whose availability can't be known
	// beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute,
	// you should add `deployment.environment`.
	ExtraResourceLabels []string `yaml:"extra_resource_attributes" env:"OTEL_EBPF_PROMETHEUS_EXTRA_RESOURCE_ATTRIBUTES" envSeparator:","`

	// ExtraSpanResourceLabels adds extra metadata labels to Prometheus span metrics from sources whose availability can't be known
	// beforehand. For example, to add the OTEL deployment.environment resource attribute as a Prometheus resource attribute,
	// you should add `deployment.environment`.
	ExtraSpanResourceLabels []string `yaml:"extra_span_resource_attributes" env:"OTEL_EBPF_PROMETHEUS_EXTRA_SPAN_RESOURCE_ATTRIBUTES" envSeparator:","`
}

func mlog() *slog.Logger {
	return slog.With("component", "prom.MetricsReporter")
}

func (p *PrometheusConfig) EndpointEnabled() bool {
	return p.Port != 0 || p.Registry != nil
}

type metricsReporter struct {
	cfg                     *PrometheusConfig
	extraMetadataLabels     []attr.Name
	extraSpanMetadataLabels []attr.Name

	input         <-chan []request.Span
	processEvents <-chan exec.ProcessEvent
	runtimeInput  <-chan []runtimemetrics.RuntimeMetricSnapshot

	obiInfo                *Expirer[prometheus.Gauge]
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
	attrCudaKernelCalls        []attributes.Field[*request.Span, string]
	attrCudaGraphCalls         []attributes.Field[*request.Span, string]
	attrCudaMemoryAllocs       []attributes.Field[*request.Span, string]
	attrCudaKernelGridSize     []attributes.Field[*request.Span, string]
	attrCudaKernelBlockSize    []attributes.Field[*request.Span, string]
	attrCudaMemoryCopies       []attributes.Field[*request.Span, string]
	attrSvcGraph               []attributes.Field[*request.Span, string]
	attrDNSLookupDuration      []attributes.Field[*request.Span, string]
	attrGenAIClientDuration    []attributes.Field[*request.Span, string]
	attrGenAIInputTokenUsage   []attributes.Field[*request.Span, string]
	attrGenAIOutputTokenUsage  []attributes.Field[*request.Span, string]

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
	cudaKernelCallsTotal  *Expirer[prometheus.Counter]
	cudaGraphCallsTotal   *Expirer[prometheus.Counter]
	cudaMemoryAllocsTotal *Expirer[prometheus.Counter]
	cudaKernelGridSize    *Expirer[prometheus.Histogram]
	cudaKernelBlockSize   *Expirer[prometheus.Histogram]
	cudaMemoryCopySize    *Expirer[prometheus.Histogram]

	// dns related metrics
	dnsLookupDuration *Expirer[prometheus.Histogram]

	// genAI related metrics
	genAIClientDuration *Expirer[prometheus.Histogram]
	genAITokenUsage     *Expirer[prometheus.Histogram]

	goRuntimeMetrics  goRuntimeMetricsCollector
	jvmRuntimeMetrics jvmRuntimeMetricsCollector

	promConnect *connector.PrometheusManager

	ctxInfo *global.ContextInfo

	is instrumentations.InstrumentationSelection

	shouldAddExemplar func(*request.Span) bool

	kubeEnabled         bool
	dockerEnabled       bool
	nodeMeta            meta.NodeMeta
	userAttribSelection attributes.Selection

	serviceMap  map[svc.UID]svc.Attrs
	pidsTracker otel.PidServiceTracker

	// for testing purposes
	createEventMetrics func(service *svc.Attrs)
	deleteEventMetrics func(service *svc.Attrs)
}

func PrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
	runtimeMetricCh *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AnyAppO11yMetric() {
			return swarm.EmptyRunFunc()
		}
		reporter, err := newReporter(
			ctx,
			ctxInfo,
			cfg,
			jointMetricsConfig,
			selectorCfg,
			unresolved,
			input,
			processEventCh,
			runtimeMetricCh,
		)
		if err != nil {
			return nil, fmt.Errorf("instantiating Prometheus endpoint: %w", err)
		}
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func spanMetricsLatencyName(mp *perapp.MetricsConfig) string {
	if mp.Features.LegacySpanMetrics() {
		return SpanMetricsLatency
	}
	return SpanMetricsLatencyOTel
}

func spanMetricsCallsName(mp *perapp.MetricsConfig) string {
	if mp.Features.LegacySpanMetrics() {
		return SpanMetricsCalls
	}
	return SpanMetricsCallsOTel
}

//nolint:cyclop
func newReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	unresolved request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
	processEventCh *msg.Queue[exec.ProcessEvent],
	runtimeMetricCh *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
) (*metricsReporter, error) {
	groups := ctxInfo.MetricAttributeGroups
	groups.Add(attributes.GroupPrometheus)

	attrsProvider, err := attributes.NewAttrSelector(groups, selectorCfg)
	if err != nil {
		return nil, fmt.Errorf("selecting metrics attributes: %w", err)
	}

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	var attrHTTPDuration, attrHTTPClientDuration, attrHTTPRequestSize, attrHTTPResponseSize, attrHTTPClientRequestSize, attrHTTPClientResponseSize, attrSvcGraph []attributes.Field[*request.Span, string]

	attributeGetters := request.SpanPromGetters(unresolved)

	if is.HTTPEnabled() {
		attrHTTPDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPServerDuration))
		attrHTTPClientDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPClientDuration))
		attrHTTPRequestSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPServerRequestSize))
		attrHTTPResponseSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPServerResponseSize))
		attrHTTPClientRequestSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPClientRequestSize))
		attrHTTPClientResponseSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.HTTPClientResponseSize))
	}

	var attrGRPCDuration, attrGRPCClientDuration []attributes.Field[*request.Span, string]

	if is.GRPCEnabled() || is.SunRPCEnabled() {
		rpcServerAttrs := attrsProvider.For(attributes.RPCServerDuration)
		rpcClientAttrs := attrsProvider.For(attributes.RPCClientDuration)
		attrGRPCDuration = attributes.PrometheusGetters(attributeGetters, rpcServerAttrs)
		attrGRPCClientDuration = attributes.PrometheusGetters(attributeGetters, rpcClientAttrs)
	}

	var attrDBClientDuration []attributes.Field[*request.Span, string]

	if is.DBEnabled() {
		attrDBClientDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.DBClientDuration))
	}

	var attrMessagingProcessDuration, attrMessagingPublishDuration []attributes.Field[*request.Span, string]

	if is.MQEnabled() {
		attrMessagingPublishDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.MessagingPublishDuration))
		attrMessagingProcessDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.MessagingProcessDuration))
	}

	var attrCudaKernelLaunchCalls []attributes.Field[*request.Span, string]
	var attrCudaGraphLaunchCalls []attributes.Field[*request.Span, string]
	var attrCudaMemoryAllocations []attributes.Field[*request.Span, string]
	var attrCudaKernelGridSize []attributes.Field[*request.Span, string]
	var attrCudaKernelBlockSize []attributes.Field[*request.Span, string]
	var attrCudaMemoryCopies []attributes.Field[*request.Span, string]

	if is.GPUEnabled() {
		attrCudaKernelLaunchCalls = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaKernelLaunchCalls))
		attrCudaGraphLaunchCalls = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaGraphLaunchCalls))
		attrCudaMemoryAllocations = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaMemoryAllocations))
		attrCudaKernelGridSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaKernelGridSize))
		attrCudaKernelBlockSize = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaKernelBlockSize))
		attrCudaMemoryCopies = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GPUCudaMemoryCopies))
	}

	var attrDNSLookupDuration []attributes.Field[*request.Span, string]

	if is.DNSEnabled() {
		attrDNSLookupDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.DNSLookupDuration))
	}

	var attrGenAIClientDuration []attributes.Field[*request.Span, string]
	var attrGenAIInputTokenUsage []attributes.Field[*request.Span, string]
	var attrGenAIOutputTokenUsage []attributes.Field[*request.Span, string]

	if is.GenAIEnabled() {
		attrGenAIClientDuration = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GenAIClientOperationDuration))
		attrGenAIInputTokenUsage = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GenAIClientInputTokenUsage))
		attrGenAIOutputTokenUsage = attributes.PrometheusGetters(attributeGetters,
			attrsProvider.For(attributes.GenAIClientOutputTokenUsage))
	}

	kubeEnabled := ctxInfo.K8sInformer.IsKubeEnabled()
	dockerEnabled := ctxInfo.DockerMetadata.IsEnabled(ctx)

	if jointMetricsConfig.Features.ServiceGraph() {
		attrs := []attr.Name{attr.Client, attr.ClientNamespace, attr.Server, attr.ServerNamespace, attr.Source}
		if kubeEnabled {
			attrs = append(attrs, attr.K8SClientCluster, attr.K8SServerCluster, attr.K8SClientNamespace, attr.K8SServerNamespace)
		}
		attrSvcGraph = attributes.PrometheusGetters(attributeGetters, attrs)
	}

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	extraMetadataLabels := parseExtraMetadata(cfg.ExtraResourceLabels)
	extraSpanMetadataLabels := parseExtraMetadata(cfg.ExtraSpanResourceLabels)
	var inputCh <-chan []request.Span
	if input != nil {
		inputCh = input.Subscribe(msg.SubscriberName("prom.InputSpans"))
	}
	runtimeMetricsEnabled := runtimemetrics.EnabledFeatures(jointMetricsConfig.Features)
	var runtimeInputCh <-chan []runtimemetrics.RuntimeMetricSnapshot
	if runtimeMetricCh != nil {
		runtimeInputCh = runtimeMetricCh.Subscribe(msg.SubscriberName("prom.RuntimeMetrics"))
	}

	mr := &metricsReporter{
		input:                      inputCh,
		processEvents:              processEventCh.Subscribe(msg.SubscriberName("prom.ProcessEvents")),
		runtimeInput:               runtimeInputCh,
		serviceMap:                 map[svc.UID]svc.Attrs{},
		pidsTracker:                otel.NewPidServiceTracker(),
		ctxInfo:                    ctxInfo,
		cfg:                        cfg,
		kubeEnabled:                kubeEnabled,
		dockerEnabled:              dockerEnabled,
		extraMetadataLabels:        extraMetadataLabels,
		extraSpanMetadataLabels:    extraSpanMetadataLabels,
		nodeMeta:                   ctxInfo.NodeMeta,
		userAttribSelection:        selectorCfg.SelectionCfg,
		is:                         is,
		promConnect:                ctxInfo.Prometheus,
		shouldAddExemplar:          exemplarFilter(cfg.ExemplarFilter),
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
		attrCudaKernelCalls:        attrCudaKernelLaunchCalls,
		attrCudaGraphCalls:         attrCudaGraphLaunchCalls,
		attrCudaMemoryAllocs:       attrCudaMemoryAllocations,
		attrCudaKernelGridSize:     attrCudaKernelGridSize,
		attrCudaKernelBlockSize:    attrCudaKernelBlockSize,
		attrCudaMemoryCopies:       attrCudaMemoryCopies,
		attrDNSLookupDuration:      attrDNSLookupDuration,
		attrGenAIClientDuration:    attrGenAIClientDuration,
		attrGenAIInputTokenUsage:   attrGenAIInputTokenUsage,
		attrGenAIOutputTokenUsage:  attrGenAIOutputTokenUsage,
		attrSvcGraph:               attrSvcGraph,
		obiInfo: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + buildInfoSuffix,
			Help: "A metric with a constant '1' value labeled by version, revision, branch, " +
				"goversion from which OBI was built, the goos and goarch for the build, and the" +
				"language of the reported services",
			ConstLabels: map[string]string{
				"goarch":    runtime.GOARCH,
				"goos":      runtime.GOOS,
				"goversion": runtime.Version(),
				"version":   buildinfo.Version,
				"revision":  buildinfo.Revision,
			},
		}, obiInfoLabelNames).MetricVec, timeNow, cfg.TTL),
		httpDuration: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerDuration.Prom,
				Help:                            "duration of HTTP service calls from the server side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		httpClientDuration: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientDuration.Prom,
				Help:                            "duration of HTTP service calls from the client side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPClientDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		grpcDuration: optionalHistogramProvider(is.GRPCEnabled() || is.SunRPCEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.RPCServerDuration.Prom,
				Help:                            "duration of RPC service calls from the server side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrGRPCDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		grpcClientDuration: optionalHistogramProvider(is.GRPCEnabled() || is.SunRPCEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.RPCClientDuration.Prom,
				Help:                            "duration of RPC service calls from the client side, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrGRPCClientDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		dbClientDuration: optionalHistogramProvider(is.DBEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.DBClientDuration.Prom,
				Help:                            "duration of db client operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrDBClientDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		msgPublishDuration: optionalHistogramProvider(is.MQEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.MessagingPublishDuration.Prom,
				Help:                            "duration of messaging client publish operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrMessagingPublishDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		msgProcessDuration: optionalHistogramProvider(is.MQEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.MessagingProcessDuration.Prom,
				Help:                            "duration of messaging client process operations, in seconds",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrMessagingProcessDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		httpRequestSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerRequestSize.Prom,
				Help:                            "size, in bytes, of the HTTP request body as received at the server side",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPRequestSize)).MetricVec, timeNow, cfg.TTL)
		}),
		httpResponseSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPServerResponseSize.Prom,
				Help:                            "size, in bytes, of the HTTP response body as received at the server side",
				Buckets:                         cfg.Buckets.ResponseSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPResponseSize)).MetricVec, timeNow, cfg.TTL)
		}),
		httpClientRequestSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientRequestSize.Prom,
				Help:                            "size, in bytes, of the HTTP request body as sent from the client side",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPClientRequestSize)).MetricVec, timeNow, cfg.TTL)
		}),
		httpClientResponseSize: optionalHistogramProvider(is.HTTPEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.HTTPClientResponseSize.Prom,
				Help:                            "size, in bytes, of the HTTP response body as sent from the client side",
				Buckets:                         cfg.Buckets.ResponseSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrHTTPClientResponseSize)).MetricVec, timeNow, cfg.TTL)
		}),
		spanMetricsLatency: optionalHistogramProvider(jointMetricsConfig.Features.SpanMetrics(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            spanMetricsLatencyName(jointMetricsConfig),
				Help:                            "duration of service calls (client and server), in seconds, in trace span metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNamesSpans(extraSpanMetadataLabels)).MetricVec, timeNow, cfg.TTL)
		}),
		spanMetricsCallsTotal: optionalCounterProvider(jointMetricsConfig.Features.SpanMetrics(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: spanMetricsCallsName(jointMetricsConfig),
				Help: "number of service calls in trace span metrics format",
			}, labelNamesSpans(extraSpanMetadataLabels)).MetricVec, timeNow, cfg.TTL)
		}),
		spanMetricsRequestSizeTotal: optionalCounterProvider(jointMetricsConfig.Features.SpanSizes(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsRequestSizes,
				Help: "size of service calls, in bytes, in trace span metrics format",
			}, labelNamesSpans(extraSpanMetadataLabels)).MetricVec, timeNow, cfg.TTL)
		}),
		spanMetricsResponseSizeTotal: optionalCounterProvider(jointMetricsConfig.Features.SpanSizes(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: SpanMetricsResponseSizes,
				Help: "size of service responses, in bytes, in trace span metrics format",
			}, labelNamesSpans(extraSpanMetadataLabels)).MetricVec, timeNow, cfg.TTL)
		}),
		tracesTargetInfo: optionalDirectGaugeProvider(jointMetricsConfig.Features.AnySpanMetrics(), func() *prometheus.GaugeVec {
			return prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: TracesTargetInfo,
				Help: "target service information in trace span metric format",
			}, labelNamesTargetInfo(kubeEnabled, dockerEnabled, &ctxInfo.NodeMeta, extraMetadataLabels, selectorCfg.SelectionCfg))
		}),
		tracesHostInfo: optionalGaugeProvider(jointMetricsConfig.Features.AppHost(), func() *Expirer[prometheus.Gauge] {
			return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
				Name: TracesHostInfo,
				Help: "A metric with a constant '1' value labeled by the host id ",
			}, []string{CloudHostIDKey}).MetricVec, timeNow, cfg.TTL)
		}),
		serviceGraphClient: optionalHistogramProvider(jointMetricsConfig.Features.ServiceGraph(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            ServiceGraphClient,
				Help:                            "duration of client service calls, in seconds, in trace service graph metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNamesSvcGraph(attrSvcGraph)).MetricVec, timeNow, cfg.TTL)
		}),
		serviceGraphServer: optionalHistogramProvider(jointMetricsConfig.Features.ServiceGraph(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            ServiceGraphServer,
				Help:                            "duration of server service calls, in seconds, in trace service graph metrics format",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNamesSvcGraph(attrSvcGraph)).MetricVec, timeNow, cfg.TTL)
		}),
		serviceGraphFailed: optionalCounterProvider(jointMetricsConfig.Features.ServiceGraph(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ServiceGraphFailed,
				Help: "number of failed service calls in trace service graph metrics format",
			}, labelNamesSvcGraph(attrSvcGraph)).MetricVec, timeNow, cfg.TTL)
		}),
		serviceGraphTotal: optionalCounterProvider(jointMetricsConfig.Features.ServiceGraph(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: ServiceGraphTotal,
				Help: "number of service calls in trace service graph metrics format",
			}, labelNamesSvcGraph(attrSvcGraph)).MetricVec, timeNow, cfg.TTL)
		}),
		targetInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: TargetInfo,
			Help: "attributes associated to a given monitored entity",
		}, labelNamesTargetInfo(kubeEnabled, dockerEnabled, &ctxInfo.NodeMeta, extraMetadataLabels, selectorCfg.SelectionCfg)),
		cudaKernelCallsTotal: optionalCounterProvider(is.GPUEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: attributes.GPUCudaKernelLaunchCalls.Prom,
				Help: "number of NVIDIA GPU cuda kernel launches",
			}, labelNames(attrCudaKernelLaunchCalls)).MetricVec, timeNow, cfg.TTL)
		}),
		cudaGraphCallsTotal: optionalCounterProvider(is.GPUEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: attributes.GPUCudaGraphLaunchCalls.Prom,
				Help: "number of NVIDIA GPU cuda graph launches",
			}, labelNames(attrCudaGraphLaunchCalls)).MetricVec, timeNow, cfg.TTL)
		}),
		cudaMemoryAllocsTotal: optionalCounterProvider(is.GPUEnabled(), func() *Expirer[prometheus.Counter] {
			return NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
				Name: attributes.GPUCudaMemoryAllocations.Prom,
				Help: "amount of NVIDIA GPU cuda allocated memory in bytes",
			}, labelNames(attrCudaMemoryAllocations)).MetricVec, timeNow, cfg.TTL)
		}),
		cudaKernelGridSize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUCudaKernelGridSize.Prom,
				Help:                            "number of blocks in the NVIDIA GPU cuda kernel grid",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrCudaKernelGridSize)).MetricVec, timeNow, cfg.TTL)
		}),
		cudaKernelBlockSize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUCudaKernelBlockSize.Prom,
				Help:                            "number of threads in the NVIDIA GPU cuda kernel block",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrCudaKernelBlockSize)).MetricVec, timeNow, cfg.TTL)
		}),
		cudaMemoryCopySize: optionalHistogramProvider(is.GPUEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GPUCudaMemoryCopies.Prom,
				Help:                            "amount of NVIDIA GPU cuda to and from memory copies",
				Buckets:                         cfg.Buckets.RequestSizeHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrCudaMemoryCopies)).MetricVec, timeNow, cfg.TTL)
		}),
		dnsLookupDuration: optionalHistogramProvider(is.DNSEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.DNSLookupDuration.Prom,
				Help:                            "measures the time taken to perform a DNS lookup",
				Buckets:                         cfg.Buckets.DurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrDNSLookupDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		genAIClientDuration: optionalHistogramProvider(is.GenAIEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GenAIClientOperationDuration.Prom,
				Help:                            "measures the time taken to perform a GenAI client request",
				Buckets:                         cfg.Buckets.GenAIClientDurationHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrGenAIClientDuration)).MetricVec, timeNow, cfg.TTL)
		}),
		// We make only one metric series, the input and output have the same name and attribute keys
		genAITokenUsage: optionalHistogramProvider(is.GenAIEnabled(), func() *Expirer[prometheus.Histogram] {
			return NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
				Name:                            attributes.GenAIClientInputTokenUsage.Prom,
				Help:                            "number of input and output tokens used for a GenAI client request",
				Buckets:                         cfg.Buckets.GenAITokenUsageHistogram,
				NativeHistogramBucketFactor:     cfg.NativeHistogram.BucketFactor,
				NativeHistogramMaxBucketNumber:  cfg.NativeHistogram.MaxBucketNumber,
				NativeHistogramMinResetDuration: cfg.NativeHistogram.MinResetDuration,
			}, labelNames(attrGenAIInputTokenUsage)).MetricVec, timeNow, cfg.TTL)
		}),
	}

	if runtimeMetricsEnabled.Runtime {
		mr.goRuntimeMetrics = newGoRuntimeMetricsCollector(
			labelNamesTargetInfo(kubeEnabled, dockerEnabled, &ctxInfo.NodeMeta, extraMetadataLabels, selectorCfg.SelectionCfg),
		)
		mr.jvmRuntimeMetrics = newJVMRuntimeMetricsCollector(cfg)
	}

	// testing aid
	mr.deleteEventMetrics = mr.deleteMetricsForService
	mr.createEventMetrics = mr.createTargetInfos

	registeredMetrics := []prometheus.Collector{mr.targetInfo}

	if !mr.cfg.DisableBuildInfo {
		registeredMetrics = append(registeredMetrics, mr.obiInfo)
	}

	if jointMetricsConfig.Features.AppRED() {
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

		if is.GRPCEnabled() || is.SunRPCEnabled() {
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

		if is.DNSEnabled() {
			registeredMetrics = append(registeredMetrics, mr.dnsLookupDuration)
		}

		if is.GenAIEnabled() {
			registeredMetrics = append(registeredMetrics, mr.genAIClientDuration)
			registeredMetrics = append(registeredMetrics, mr.genAITokenUsage)
		}
	}

	if jointMetricsConfig.Features.SpanMetrics() {
		registeredMetrics = append(registeredMetrics,
			mr.spanMetricsLatency,
			mr.spanMetricsCallsTotal,
		)
	}

	if jointMetricsConfig.Features.SpanSizes() {
		registeredMetrics = append(registeredMetrics,
			mr.spanMetricsRequestSizeTotal,
			mr.spanMetricsResponseSizeTotal,
		)
	}

	if jointMetricsConfig.Features.ServiceGraph() {
		registeredMetrics = append(registeredMetrics,
			mr.serviceGraphClient,
			mr.serviceGraphServer,
			mr.serviceGraphFailed,
			mr.serviceGraphTotal,
		)
	}

	if jointMetricsConfig.Features.AnySpanMetrics() {
		registeredMetrics = append(registeredMetrics, mr.tracesTargetInfo)
	}

	if jointMetricsConfig.Features.AppHost() {
		registeredMetrics = append(registeredMetrics, mr.tracesHostInfo)
	}

	if runtimeMetricsEnabled.Runtime {
		registeredMetrics = append(registeredMetrics, mr.goRuntimeMetrics.collectors()...)
		registeredMetrics = append(registeredMetrics, mr.jvmRuntimeMetrics.collectors()...)
	}

	if is.GPUEnabled() {
		registeredMetrics = append(registeredMetrics,
			mr.cudaKernelCallsTotal,
			mr.cudaGraphCallsTotal,
			mr.cudaMemoryAllocsTotal,
			mr.cudaKernelGridSize,
			mr.cudaKernelBlockSize,
			mr.cudaMemoryCopySize,
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
	if r.runtimeInput != nil {
		go r.watchForRuntimeMetrics(ctx)
	}
	swarms.ForEachInput(ctx, r.input, nil, func(spans []request.Span) {
		for i := range spans {
			r.observe(&spans[i])
		}
	})
}

func (r *metricsReporter) otelMetricsObserved(span *request.Span) bool {
	return span.Service.Features.AppRED() && !span.Service.ExportsOTelMetrics()
}

func (r *metricsReporter) otelSpanMetricsObserved(span *request.Span) bool {
	return span.Service.Features.AnySpanMetrics() && !span.Service.ExportsOTelMetricsSpan() && !span.IsDNSSpan()
}

func (r *metricsReporter) otelSpanFiltered(span *request.Span) bool {
	return span.InternalSignal() || request.IgnoreMetrics(span)
}

func exemplarFilter(filter string) func(*request.Span) bool {
	switch filter {
	default:
		mlog().Warn("invalid Prometheus' exemplar_filter value. Defaulting to always_off", "filter", filter)
		fallthrough
	case "always_off":
		return func(*request.Span) bool {
			return false
		}
	case "trace_based":
		return func(span *request.Span) bool {
			return span.TraceFlags&ebpfcommon.TPFlagSampled != 0 && span.TraceID.IsValid()
		}
	case "always_on":
		return func(span *request.Span) bool {
			return span.TraceID.IsValid()
		}
	}
}

// traceExemplar returns prometheus labels with trace and span IDs for exemplar reporting.
func traceExemplar(span *request.Span) prometheus.Labels {
	return prometheus.Labels{
		"traceID": span.TraceID.String(),
		"spanID":  span.SpanID.String(),
	}
}

// observeHistogram observes a value into a histogram, attaching an exemplar when applicable.
func (r *metricsReporter) observeHistogram(h prometheus.Histogram, value float64, span *request.Span) {
	if r.shouldAddExemplar(span) {
		if observer, ok := h.(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(value, traceExemplar(span))
			return
		}
	}

	h.Observe(value)
}

// addCounter adds a value to a counter, attaching an exemplar when applicable.
func (r *metricsReporter) addCounter(c prometheus.Counter, value float64, span *request.Span) {
	if r.shouldAddExemplar(span) {
		if adder, ok := c.(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(value, traceExemplar(span))
			return
		}
	}

	c.Add(value)
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
	r.obiInfo.WithLabelValues(span.Service.SDKLanguage.String()).Metric.Set(1.0)
	if span.Service.Features.AppHost() {
		r.tracesHostInfo.WithLabelValues(r.nodeMeta.HostID).Metric.Set(1.0)
	}
	duration := t.End.Sub(t.RequestStart).Seconds()

	if r.otelMetricsObserved(span) {
		switch span.Type {
		case request.EventTypeHTTP:
			// JSON-RPC over HTTP gets recorded as RPC server metrics
			if span.SubType == request.HTTPSubtypeJSONRPC && r.is.GRPCEnabled() {
				r.observeHistogram(r.grpcDuration.WithLabelValues(labelValues(span, r.attrGRPCDuration)...).Metric, duration, span)
			} else if r.is.HTTPEnabled() {
				r.observeHistogram(r.httpDuration.WithLabelValues(labelValues(span, r.attrHTTPDuration)...).Metric, duration, span)
				r.observeHistogram(r.httpRequestSize.WithLabelValues(labelValues(span, r.attrHTTPRequestSize)...).Metric, float64(span.RequestBodyLength()), span)
				r.observeHistogram(r.httpResponseSize.WithLabelValues(labelValues(span, r.attrHTTPResponseSize)...).Metric, float64(span.ResponseBodyLength()), span)
			}
		case request.EventTypeHTTPClient:
			// HTTP client subtypes that are database calls get recorded as db client metrics
			switch {
			case r.is.DBEnabled() && (span.SubType == request.HTTPSubtypeSQLPP || span.SubType == request.HTTPSubtypeElasticsearch):
				r.observeHistogram(r.dbClientDuration.WithLabelValues(labelValues(span, r.attrDBClientDuration)...).Metric, duration, span)
			case span.SubType == request.HTTPSubtypeJSONRPC && r.is.GRPCEnabled():
				// JSON-RPC client calls over HTTP get recorded as RPC client metrics
				r.observeHistogram(r.grpcClientDuration.WithLabelValues(labelValues(span, r.attrGRPCClientDuration)...).Metric, duration, span)
			case r.is.GenAIEnabled() && request.IsGenAISubtype(span.SubType):
				r.observeHistogram(r.genAIClientDuration.WithLabelValues(labelValues(span, r.attrGenAIClientDuration)...).Metric, duration, span)
				r.observeHistogram(r.genAITokenUsage.WithLabelValues(labelValues(span, r.attrGenAIInputTokenUsage)...).Metric, float64(span.GenAIInputTokens()), span)
				r.observeHistogram(r.genAITokenUsage.WithLabelValues(labelValues(span, r.attrGenAIOutputTokenUsage)...).Metric, float64(span.GenAIOutputTokens()), span)
			default:
				if r.is.HTTPEnabled() {
					r.observeHistogram(r.httpClientDuration.WithLabelValues(labelValues(span, r.attrHTTPClientDuration)...).Metric, duration, span)
					r.observeHistogram(r.httpClientRequestSize.WithLabelValues(labelValues(span, r.attrHTTPClientRequestSize)...).Metric, float64(span.RequestBodyLength()), span)
					r.observeHistogram(r.httpClientResponseSize.WithLabelValues(labelValues(span, r.attrHTTPClientResponseSize)...).Metric, float64(span.ResponseBodyLength()), span)
				}
			}
		case request.EventTypeGRPC:
			if r.is.GRPCEnabled() {
				r.observeHistogram(r.grpcDuration.WithLabelValues(labelValues(span, r.attrGRPCDuration)...).Metric, duration, span)
			}
		case request.EventTypeGRPCClient:
			if r.is.GRPCEnabled() {
				r.observeHistogram(r.grpcClientDuration.WithLabelValues(labelValues(span, r.attrGRPCClientDuration)...).Metric, duration, span)
			}
		case request.EventTypeSunRPCClient:
			if r.is.SunRPCEnabled() {
				r.observeHistogram(r.grpcClientDuration.WithLabelValues(labelValues(span, r.attrGRPCClientDuration)...).Metric, duration, span)
			}
		case request.EventTypeSunRPCServer:
			if r.is.SunRPCEnabled() {
				r.observeHistogram(r.grpcDuration.WithLabelValues(labelValues(span, r.attrGRPCDuration)...).Metric, duration, span)
			}
		case request.EventTypeRedisClient, request.EventTypeSQLClient, request.EventTypeRedisServer, request.EventTypeMongoClient, request.EventTypeCouchbaseClient, request.EventTypeMemcachedClient, request.EventTypeMemcachedServer, request.EventTypeAerospikeClient:
			if r.is.DBEnabled() {
				r.observeHistogram(r.dbClientDuration.WithLabelValues(labelValues(span, r.attrDBClientDuration)...).Metric, duration, span)
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if r.is.KafkaEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					r.observeHistogram(r.msgPublishDuration.WithLabelValues(labelValues(span, r.attrMsgPublishDuration)...).Metric, duration, span)
				case request.MessagingProcess:
					r.observeHistogram(r.msgProcessDuration.WithLabelValues(labelValues(span, r.attrMsgProcessDuration)...).Metric, duration, span)
				}
			}
		case request.EventTypeMQTTClient, request.EventTypeMQTTServer:
			if r.is.MQTTEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					r.observeHistogram(r.msgPublishDuration.WithLabelValues(labelValues(span, r.attrMsgPublishDuration)...).Metric, duration, span)
				case request.MessagingProcess:
					r.observeHistogram(r.msgProcessDuration.WithLabelValues(labelValues(span, r.attrMsgProcessDuration)...).Metric, duration, span)
				}
			}
		case request.EventTypeNATSClient, request.EventTypeNATSServer:
			if r.is.NATSEnabled() {
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
		case request.EventTypeAMQPClient:
			if r.is.AMQPEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					r.observeHistogram(r.msgPublishDuration.WithLabelValues(labelValues(span, r.attrMsgPublishDuration)...).Metric, duration, span)
				case request.MessagingProcess:
					r.observeHistogram(r.msgProcessDuration.WithLabelValues(labelValues(span, r.attrMsgProcessDuration)...).Metric, duration, span)
				}
			}
		case request.EventTypeGPUCudaKernelLaunch:
			if r.is.GPUEnabled() {
				r.addCounter(r.cudaKernelCallsTotal.WithLabelValues(labelValues(span, r.attrCudaKernelCalls)...).Metric, 1, span)
				r.observeHistogram(r.cudaKernelGridSize.WithLabelValues(labelValues(span, r.attrCudaKernelGridSize)...).Metric, float64(span.ContentLength), span)
				r.observeHistogram(r.cudaKernelBlockSize.WithLabelValues(labelValues(span, r.attrCudaKernelBlockSize)...).Metric, float64(span.SubType), span)
			}
		case request.EventTypeGPUCudaGraphLaunch:
			if r.is.GPUEnabled() {
				r.addCounter(r.cudaGraphCallsTotal.WithLabelValues(labelValues(span, r.attrCudaKernelCalls)...).Metric, 1, span)
			}
		case request.EventTypeGPUCudaMalloc:
			if r.is.GPUEnabled() {
				r.addCounter(r.cudaMemoryAllocsTotal.WithLabelValues(labelValues(span, r.attrCudaMemoryAllocs)...).Metric, float64(span.ContentLength), span)
			}
		case request.EventTypeGPUCudaMemcpy:
			if r.is.GPUEnabled() {
				r.observeHistogram(r.cudaMemoryCopySize.WithLabelValues(labelValues(span, r.attrCudaMemoryCopies)...).Metric, float64(span.ContentLength), span)
			}
		case request.EventTypeDNS:
			if r.is.DNSEnabled() {
				r.observeHistogram(r.dnsLookupDuration.WithLabelValues(labelValues(span, r.attrDNSLookupDuration)...).Metric, duration, span)
			}
		}
	}

	if r.otelSpanMetricsObserved(span) {
		if span.Service.Features.SpanMetrics() {
			lv := r.labelValuesSpans(span)
			r.observeHistogram(r.spanMetricsLatency.WithLabelValues(lv...).Metric, duration, span)
			r.addCounter(r.spanMetricsCallsTotal.WithLabelValues(lv...).Metric, 1, span)
		}

		if span.Service.Features.SpanSizes() {
			lv := r.labelValuesSpans(span)
			r.addCounter(r.spanMetricsRequestSizeTotal.WithLabelValues(lv...).Metric, float64(span.RequestBodyLength()), span)
			r.addCounter(r.spanMetricsResponseSizeTotal.WithLabelValues(lv...).Metric, float64(span.ResponseBodyLength()), span)
		}

		if span.Service.Features.ServiceGraph() {
			if !span.IsSelfReferenceSpan() || r.cfg.AllowServiceGraphSelfReferences {
				lvg := labelValuesSvcGraph(span, r.attrSvcGraph, &r.pidsTracker)

				if span.IsClientSpan() {
					r.observeHistogram(r.serviceGraphClient.WithLabelValues(lvg...).Metric, duration, span)
					// If we managed to resolve the remote name only, we check to see
					// we are not instrumenting the server service, then and only then,
					// we generate client span count for service graph total
					if otel.ClientSpanToUninstrumentedService(&r.pidsTracker, span) {
						r.addCounter(r.serviceGraphTotal.WithLabelValues(lvg...).Metric, 1, span)
					}
				} else {
					r.observeHistogram(r.serviceGraphServer.WithLabelValues(lvg...).Metric, duration, span)
					r.addCounter(r.serviceGraphTotal.WithLabelValues(lvg...).Metric, 1, span)
				}
				if request.SpanStatusCode(span) == request.StatusCodeError {
					r.addCounter(r.serviceGraphFailed.WithLabelValues(lvg...).Metric, 1, span)
				}
			}
		}
	}
}

func labelNamesSpans(extraMetadataLabelNames []attr.Name) []string {
	names := []string{
		serviceNameKey,
		serviceNamespaceKey,
		spanNameKey,
		statusCodeKey,
		spanKindKey,
		serviceInstanceKey,
		serviceJobKey,
		sourceKey,
		telemetryLanguageKey,
	}

	for _, mdn := range extraMetadataLabelNames {
		names = append(names, mdn.Prom())
	}

	return names
}

func (r *metricsReporter) labelValuesSpans(span *request.Span) []string {
	values := []string{
		span.Service.UID.Name,
		span.Service.UID.Namespace,
		span.TraceName(),
		request.SpanStatusCode(span),
		span.ServiceGraphKind(),
		span.Service.UID.Instance, // app instance ID
		span.Service.Job(),
		attr.VendorPrefix,
		span.Service.SDKLanguage.String(),
	}

	for _, k := range r.extraSpanMetadataLabels {
		values = append(values, span.Service.Metadata[k])
	}

	return values
}

type targetInfoResourceLabel struct {
	name  attr.Name
	value string
}

func baseTargetInfoLabelNames() []attr.Name {
	return []attr.Name{
		attr.HostID,
		attr.HostName,
		attr.ServiceName,
		attr.ServiceNamespace,
		attr.Instance,
		attr.Job,
		attr.TelemetrySDKLanguage,
		attr.Name("telemetry.sdk.name"),
		attr.Name("telemetry.sdk.version"),
		attr.Name("telemetry.distro.name"),
		attr.Name("telemetry.distro.version"),
		attr.Source,
		attr.Name("os.type"),
	}
}

func k8sTargetInfoLabelNames() []attr.Name {
	return []attr.Name{
		attr.K8sNamespaceName,
		attr.K8sPodName,
		attr.K8sContainerName,
		attr.K8sNodeName,
		attr.K8sPodUID,
		attr.K8sPodStartTime,
		attr.K8sDeploymentName,
		attr.K8sReplicaSetName,
		attr.K8sStatefulSetName,
		attr.K8sJobName,
		attr.K8sCronJobName,
		attr.K8sDaemonSetName,
		attr.K8sClusterName,
		attr.K8sKind,
		attr.K8sOwnerName,
	}
}

func targetInfoLabelNames(kubeEnabled, dockerEnabled bool, nodeMeta *meta.NodeMeta, extraMetadataLabelNames []attr.Name) []attr.Name {
	names := baseTargetInfoLabelNames()

	if kubeEnabled {
		names = append(names, k8sTargetInfoLabelNames()...)
	}
	if dockerEnabled {
		names = append(names, attr.ContainerID, attr.ContainerName)
	}

	for _, entry := range nodeMeta.Metadata {
		names = append(names, entry.Key)
	}

	names = append(names, extraMetadataLabelNames...)

	return names
}

func labelNamesTargetInfo(
	kubeEnabled, dockerEnabled bool,
	nodeMeta *meta.NodeMeta,
	extraMetadataLabelNames []attr.Name,
	attrSelector attributes.Selection,
) []string {
	labelNames := targetInfoLabelNames(kubeEnabled, dockerEnabled, nodeMeta, extraMetadataLabelNames)
	names := make([]string, 0, len(labelNames))
	for _, name := range labelNames {
		if otelcfg.ResourceAttributeSelected(string(name), attrSelector) {
			names = append(names, name.Prom())
		}
	}

	return names
}

func (r *metricsReporter) labelValuesTargetInfo(service *svc.Attrs) []string {
	return r.labelValuesForNodeMeta(service, &r.nodeMeta)
}

func (r *metricsReporter) labelValuesForNodeMeta(service *svc.Attrs, nodeMeta *meta.NodeMeta) []string {
	labels := []targetInfoResourceLabel{
		{name: attr.HostID, value: nodeMeta.HostID},
		{name: attr.HostName, value: service.HostName},
		{name: attr.ServiceName, value: service.UID.Name},
		{name: attr.ServiceNamespace, value: service.UID.Namespace},
		{name: attr.Instance, value: service.UID.Instance}, // app instance ID
		{name: attr.Job, value: service.Job()},
		{name: attr.TelemetrySDKLanguage, value: service.SDKLanguage.String()},
		{name: attr.Name("telemetry.sdk.name"), value: attr.VendorSDKName},
		{name: attr.Name("telemetry.sdk.version"), value: attr.VendorSDKVersion},
		{name: attr.Name("telemetry.distro.name"), value: attr.TelemetryDistroName},
		{name: attr.Name("telemetry.distro.version"), value: attr.TelemetryDistroVersion},
		{name: attr.Source, value: attr.VendorPrefix},
		{name: attr.Name("os.type"), value: "linux"},
	}

	if r.kubeEnabled {
		for _, name := range k8sTargetInfoLabelNames() {
			labels = append(labels, targetInfoResourceLabel{name: name, value: service.Metadata[name]})
		}
	}

	if r.dockerEnabled {
		labels = append(labels,
			targetInfoResourceLabel{name: attr.ContainerID, value: service.Metadata[attr.ContainerID]},
			targetInfoResourceLabel{name: attr.ContainerName, value: service.Metadata[attr.ContainerName]},
		)
	}

	for _, entry := range nodeMeta.Metadata {
		labels = append(labels, targetInfoResourceLabel{name: entry.Key, value: entry.Value})
	}

	for _, k := range r.extraMetadataLabels {
		labels = append(labels, targetInfoResourceLabel{name: k, value: service.Metadata[k]})
	}

	values := make([]string, 0, len(labels))
	for _, label := range labels {
		if otelcfg.ResourceAttributeSelected(string(label.name), r.userAttribSelection) {
			values = append(values, label.value)
		}
	}

	return values
}

func labelNames[T any](getters []attributes.Field[T, string]) []string {
	labels := make([]string, 0, len(getters))
	for _, label := range getters {
		labels = append(labels, label.ExposedName)
	}
	return labels
}

func labelNamesSvcGraph(getters []attributes.Field[*request.Span, string]) []string {
	return append(labelNames(getters), attr.ConnectionType.Prom())
}

func labelValuesSvcGraph(span *request.Span, getters []attributes.Field[*request.Span, string], tracker *otel.PidServiceTracker) []string {
	return append(labelValues(span, getters), otel.ConnectionTypeForSpan(span, tracker))
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
	if !service.Features.AnySpanMetrics() {
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

func (r *metricsReporter) deleteTargetInfoMetric(service *svc.Attrs) {
	targetInfoLabelValues := r.labelValuesTargetInfo(service)
	r.targetInfo.DeleteLabelValues(targetInfoLabelValues...)
}

func (r *metricsReporter) deleteTracesTargetInfoMetric(service *svc.Attrs) {
	if !service.Features.AnySpanMetrics() {
		return
	}
	targetInfoLabelValues := r.labelValuesTargetInfo(service)
	r.tracesTargetInfo.DeleteLabelValues(targetInfoLabelValues...)
}

func (r *metricsReporter) setupPIDToServiceRelationship(pid app.PID, uid svc.UID) {
	r.pidsTracker.AddPID(pid, uid)
}

func (r *metricsReporter) disassociatePIDFromService(pid app.PID) (bool, svc.UID) {
	return r.pidsTracker.RemovePID(pid)
}

func (r *metricsReporter) createTargetInfos(service *svc.Attrs) {
	if service == nil || !service.ExportModes.CanExportMetrics() {
		return
	}

	r.createTargetInfo(service)
	r.createTracesTargetInfo(service)
}

func (r *metricsReporter) deleteTargetInfoMetrics(service *svc.Attrs) {
	if service == nil || !service.ExportModes.CanExportMetrics() {
		return
	}

	r.deleteTargetInfoMetric(service)
	r.deleteTracesTargetInfoMetric(service)
}

func (r *metricsReporter) deleteMetricsForService(service *svc.Attrs) {
	r.deleteTargetInfoMetrics(service)
	r.deleteRuntimeMetrics(service)
}

func (r *metricsReporter) deleteTargetInfos(uid svc.UID, service *svc.Attrs) {
	orig := r.origService(uid, service)
	if orig == nil || !orig.ExportModes.CanExportMetrics() {
		return
	}

	r.deleteEventMetrics(orig)
}

func (r *metricsReporter) handleProcessEvent(pe exec.ProcessEvent, log *slog.Logger) {
	snap := pe.File.ServiceAttrs()
	pid := pe.File.Pid()
	log.Debug("Received new process event", "event type", pe.Type, "pid", pid, "attrs", snap.UID)
	uid := snap.UID

	if pe.Type == exec.ProcessEventCreated {
		// Handle the case when the PID changed its feathers, e.g. got new metadata impacting the service name.
		// There's no new PID, just an update to the metadata.
		if staleUID, exists := r.pidsTracker.TracksPID(pid); exists && !staleUID.Equals(&uid) {
			log.Debug("updating older service definition", "from", staleUID, "new", uid)
			r.pidsTracker.ReplaceUID(staleUID, uid)
			if origAttrs, ok := r.serviceMap[staleUID]; ok {
				log.Debug("updating service attributes for", "service", uid)
				r.deleteEventMetrics(&origAttrs)
				delete(r.serviceMap, staleUID)
				r.serviceMap[uid] = snap
				r.createEventMetrics(&snap)
				// we don't setup the pid again, we just replaced the metrics it's associated with
			}
			return
		}

		// Handle the case when we have new labels for same service
		// It could be a brand new PID with this information, so we fall through after deleting
		// the old target info
		if origAttrs, ok := r.serviceMap[uid]; ok {
			log.Debug("updating stale attributes for", "service", uid)
			r.deleteEventMetrics(&origAttrs)
		}

		r.createEventMetrics(&snap)
		r.serviceMap[uid] = snap
		r.setupPIDToServiceRelationship(pid, uid)
	} else {
		if deleted, origUID := r.disassociatePIDFromService(pid); deleted {
			mlog().Debug("deleting infos for", "pid", pid, "attrs", uid)
			r.deleteTargetInfos(origUID, &snap)
			if r.tracesHostInfo != nil && r.pidsTracker.Count() == 0 {
				mlog().Debug("No more PIDs tracked, expiring host info metric")
				r.tracesHostInfo.entries.DeleteAll()
			}
			delete(r.serviceMap, origUID)
		}
	}
}

func (r *metricsReporter) watchForProcessEvents(ctx context.Context) {
	log := mlog().With("function", "watchForProcessEvents")
	swarms.ForEachInput(ctx, r.processEvents, log.Debug, func(pe exec.ProcessEvent) {
		r.handleProcessEvent(pe, log)
	})
}
