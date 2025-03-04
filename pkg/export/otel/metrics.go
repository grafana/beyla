package otel

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/instrumentations"
	"github.com/grafana/beyla/v2/pkg/export/otel/metric"
	instrument "github.com/grafana/beyla/v2/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

const (
	// SpanMetricsLatency and rest of metrics below haven't been yet moved to the
	// pkg/internal/export/metric package as we are disabling user-provided attribute
	// selection for them. They are very specific metrics with an opinionated format
	// for Span Metrics and Service Graph Metrics functionalities
	SpanMetricsLatency = "traces_spanmetrics_latency"
	SpanMetricsCalls   = "traces_spanmetrics_calls_total"
	SpanMetricsSizes   = "traces_spanmetrics_size_total"
	TracesTargetInfo   = "traces_target_info"
	TracesHostInfo     = "traces_host_info"
	ServiceGraphClient = "traces_service_graph_request_client"
	ServiceGraphServer = "traces_service_graph_request_server"
	ServiceGraphFailed = "traces_service_graph_request_failed_total"
	ServiceGraphTotal  = "traces_service_graph_request_total"

	UsualPortGRPC = "4317"
	UsualPortHTTP = "4318"

	AggregationExplicit    = "explicit_bucket_histogram"
	AggregationExponential = "base2_exponential_bucket_histogram"

	FeatureNetwork          = "network"
	FeatureNetworkInterZone = "network_inter_zone"
	FeatureApplication      = "application"
	FeatureSpan             = "application_span"
	FeatureGraph            = "application_service_graph"
	FeatureProcess          = "application_process"
	FeatureEBPF             = "ebpf"
)

// GrafanaHostIDKey is the same attribute Key as HostIDKey, but used for
// traces_target_info
const GrafanaHostIDKey = attribute.Key("grafana.host.id")

type MetricsConfig struct {
	Interval time.Duration `yaml:"interval" env:"BEYLA_METRICS_INTERVAL"`
	// OTELIntervalMS supports metric intervals as specified by the standard OTEL definition.
	// BEYLA_METRICS_INTERVAL takes precedence over it.
	OTELIntervalMS int `env:"OTEL_METRIC_EXPORT_INTERVAL"`

	CommonEndpoint  string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	Protocol        Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	MetricsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"BEYLA_OTEL_INSECURE_SKIP_VERIFY"`

	Buckets              Buckets `yaml:"buckets"`
	HistogramAggregation string  `yaml:"histogram_aggregation" env:"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"BEYLA_METRICS_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"BEYLA_OTEL_SDK_LOG_LEVEL"`

	// Features of metrics that are can be exported. Accepted values are "application" and "network".
	// envDefault is provided to avoid breaking changes
	Features []string `yaml:"features" env:"BEYLA_OTEL_METRICS_FEATURES,expand" envDefault:"${BEYLA_OTEL_METRIC_FEATURES}"  envSeparator:","`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"BEYLA_OTEL_METRICS_INSTRUMENTATIONS" envSeparator:","`

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL time.Duration `yaml:"ttl" env:"BEYLA_OTEL_METRICS_TTL"`

	AllowServiceGraphSelfReferences bool `yaml:"allow_service_graph_self_references" env:"BEYLA_OTEL_ALLOW_SERVICE_GRAPH_SELF_REFERENCES"`

	// Grafana configuration needs to be explicitly set up before building the graph
	Grafana *GrafanaOTLP `yaml:"-"`
}

func (m *MetricsConfig) GetProtocol() Protocol {
	if m.MetricsProtocol != "" {
		return m.MetricsProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.GuessProtocol()
}

func (m *MetricsConfig) GetInterval() time.Duration {
	if m.Interval == 0 {
		return time.Duration(m.OTELIntervalMS) * time.Millisecond
	}
	return m.Interval
}

func (m *MetricsConfig) GuessProtocol() Protocol {
	// If no explicit protocol is set, we guess it it from the metrics enpdoint port
	// (assuming it uses a standard port or a development-like form like 14317, 24317, 14318...)
	ep, _, err := parseMetricsEndpoint(m)
	if err == nil {
		if strings.HasSuffix(ep.Port(), UsualPortGRPC) {
			return ProtocolGRPC
		} else if strings.HasSuffix(ep.Port(), UsualPortHTTP) {
			return ProtocolHTTPProtobuf
		}
	}
	// Otherwise we return default protocol according to the latest specification:
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md?plain=1#L53
	return ProtocolHTTPProtobuf
}

func (m *MetricsConfig) OTLPMetricsEndpoint() (string, bool) {
	return ResolveOTLPEndpoint(m.MetricsEndpoint, m.CommonEndpoint, m.Grafana)
}

// EndpointEnabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
// nolint:gocritic
func (m *MetricsConfig) EndpointEnabled() bool {
	return m.CommonEndpoint != "" || m.MetricsEndpoint != "" || m.Grafana.MetricsEnabled()
}

func (m *MetricsConfig) SpanMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureSpan)
}

func (m *MetricsConfig) ServiceGraphMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureGraph)
}

func (m *MetricsConfig) OTelMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureApplication)
}

func (m *MetricsConfig) NetworkMetricsEnabled() bool {
	return m.NetworkFlowBytesEnabled() || m.NetworkInterzoneMetricsEnabled()
}

func (m *MetricsConfig) NetworkFlowBytesEnabled() bool {
	return slices.Contains(m.Features, FeatureNetwork)
}

func (m *MetricsConfig) NetworkInterzoneMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureNetworkInterZone)
}

func (m *MetricsConfig) Enabled() bool {
	return m.EndpointEnabled() && (m.OTelMetricsEnabled() || m.SpanMetricsEnabled() || m.ServiceGraphMetricsEnabled() || m.NetworkMetricsEnabled())
}

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx        context.Context
	cfg        *MetricsConfig
	hostID     string
	attributes *attributes.AttrSelector
	exporter   sdkmetric.Exporter
	reporters  ReporterPool[*svc.Attrs, *Metrics]
	is         instrumentations.InstrumentationSelection

	// user-selected fields for each of the reported metrics
	attrHTTPDuration          []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientDuration    []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCServer            []attributes.Field[*request.Span, attribute.KeyValue]
	attrGRPCClient            []attributes.Field[*request.Span, attribute.KeyValue]
	attrDBClient              []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingPublish      []attributes.Field[*request.Span, attribute.KeyValue]
	attrMessagingProcess      []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPRequestSize       []attributes.Field[*request.Span, attribute.KeyValue]
	attrHTTPClientRequestSize []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUKernelCalls        []attributes.Field[*request.Span, attribute.KeyValue]
	attrGPUMemoryAllocations  []attributes.Field[*request.Span, attribute.KeyValue]
}

// Metrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by Beyla.
type Metrics struct {
	ctx      context.Context
	service  *svc.Attrs
	provider *metric.MeterProvider

	// IMPORTANT! Don't forget to clean each Expirer in cleanupAllMetricsInstances method
	httpDuration          *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpClientDuration    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	grpcDuration          *Expirer[*request.Span, instrument.Float64Histogram, float64]
	grpcClientDuration    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	dbClientDuration      *Expirer[*request.Span, instrument.Float64Histogram, float64]
	msgPublishDuration    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	msgProcessDuration    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpRequestSize       *Expirer[*request.Span, instrument.Float64Histogram, float64]
	httpClientRequestSize *Expirer[*request.Span, instrument.Float64Histogram, float64]
	// trace span metrics
	spanMetricsLatency    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	spanMetricsCallsTotal *Expirer[*request.Span, instrument.Int64Counter, int64]
	spanMetricsSizeTotal  *Expirer[*request.Span, instrument.Float64Counter, float64]
	serviceGraphClient    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	serviceGraphServer    *Expirer[*request.Span, instrument.Float64Histogram, float64]
	serviceGraphFailed    *Expirer[*request.Span, instrument.Int64Counter, int64]
	serviceGraphTotal     *Expirer[*request.Span, instrument.Int64Counter, int64]
	tracesTargetInfo      instrument.Int64UpDownCounter
	gpuKernelCallsTotal   *Expirer[*request.Span, instrument.Int64Counter, int64]
	gpuMemoryAllocsTotal  *Expirer[*request.Span, instrument.Int64Counter, int64]
}

func ReportMetrics(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
	userAttribSelection attributes.Selection,
) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !cfg.Enabled() {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newMetricsReporter(ctx, ctxInfo, cfg, userAttribSelection)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}

		if mr.cfg.SpanMetricsEnabled() || mr.cfg.ServiceGraphMetricsEnabled() {
			hostMetrics := mr.newMetricsInstance(nil)
			hostMeter := hostMetrics.provider.Meter(reporterName)
			err := mr.setupHostInfoMeter(hostMeter)
			if err != nil {
				return nil, fmt.Errorf("setting up host metrics: %w", err)
			}
		}

		return mr.reportMetrics, nil
	}
}

func newMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
	userAttribSelection attributes.Selection,
) (*MetricsReporter, error) {
	log := mlog()

	attribProvider, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, userAttribSelection)
	if err != nil {
		return nil, fmt.Errorf("attributes select: %w", err)
	}

	is := instrumentations.NewInstrumentationSelection(cfg.Instrumentations)

	mr := MetricsReporter{
		ctx:        ctx,
		cfg:        cfg,
		is:         is,
		attributes: attribProvider,
		hostID:     ctxInfo.HostID,
	}
	// initialize attribute getters
	if is.HTTPEnabled() {
		mr.attrHTTPDuration = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPServerDuration))
		mr.attrHTTPClientDuration = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPClientDuration))
		mr.attrHTTPRequestSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPServerRequestSize))
		mr.attrHTTPClientRequestSize = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.HTTPClientRequestSize))
	}
	if is.GRPCEnabled() {
		mr.attrGRPCServer = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.RPCServerDuration))
		mr.attrGRPCClient = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.RPCClientDuration))
	}

	if is.DBEnabled() {
		mr.attrDBClient = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.DBClientDuration))
	}

	if is.MQEnabled() {
		mr.attrMessagingPublish = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.MessagingPublishDuration))
		mr.attrMessagingProcess = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.MessagingProcessDuration))
	}

	if is.GPUEnabled() {
		mr.attrGPUKernelCalls = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUKernelLaunchCalls))
		mr.attrGPUMemoryAllocations = attributes.OpenTelemetryGetters(
			request.SpanOTELGetters, mr.attributes.For(attributes.GPUMemoryAllocations))
	}

	mr.reporters = NewReporterPool[*svc.Attrs, *Metrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *expirable[*Metrics]) {
			if mr.cfg.SpanMetricsEnabled() {
				attrOpt := instrument.WithAttributeSet(mr.metricResourceAttributes(v.value.service))
				v.value.tracesTargetInfo.Add(mr.ctx, 1, attrOpt)
			}

			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.value.cleanupAllMetricsInstances()
			go func() {
				if err := v.value.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)
	// Instantiate the OTLP HTTP or GRPC metrics exporter
	exporter, err := InstantiateMetricsExporter(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	mr.exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	return &mr, nil
}

func (mr *MetricsReporter) otelMetricOptions(mlog *slog.Logger) []metric.Option {
	var opts []metric.Option
	if !mr.cfg.OTelMetricsEnabled() {
		return opts
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	if mr.is.HTTPEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.HTTPServerDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPServerRequestSize.OTEL, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.HTTPClientRequestSize.OTEL, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.GRPCEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.RPCServerDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.RPCClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.DBEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.DBClientDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	if mr.is.MQEnabled() {
		opts = append(opts,
			metric.WithView(otelHistogramConfig(attributes.MessagingPublishDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(attributes.MessagingProcessDuration.OTEL, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		)
	}

	return opts
}

func (mr *MetricsReporter) spanMetricOptions(mlog *slog.Logger) []metric.Option {
	if !mr.cfg.SpanMetricsEnabled() {
		return []metric.Option{}
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	return []metric.Option{
		metric.WithView(otelHistogramConfig(SpanMetricsLatency, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
	}
}

func (mr *MetricsReporter) graphMetricOptions(mlog *slog.Logger) []metric.Option {
	if !mr.cfg.ServiceGraphMetricsEnabled() {
		return []metric.Option{}
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	return []metric.Option{
		metric.WithView(otelHistogramConfig(ServiceGraphClient, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(ServiceGraphServer, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
	}
}

// nolint: cyclop
func (mr *MetricsReporter) setupOtelMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.OTelMetricsEnabled() {
		return nil
	}

	if mr.is.HTTPEnabled() {
		httpDuration, err := meter.Float64Histogram(attributes.HTTPServerDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating http duration histogram metric: %w", err)
		}
		m.httpDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpDuration, mr.attrHTTPDuration, timeNow, mr.cfg.TTL)

		httpClientDuration, err := meter.Float64Histogram(attributes.HTTPClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating http duration histogram metric: %w", err)
		}
		m.httpClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpClientDuration, mr.attrHTTPClientDuration, timeNow, mr.cfg.TTL)

		httpRequestSize, err := meter.Float64Histogram(attributes.HTTPServerRequestSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http size histogram metric: %w", err)
		}
		m.httpRequestSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpRequestSize, mr.attrHTTPRequestSize, timeNow, mr.cfg.TTL)

		httpClientRequestSize, err := meter.Float64Histogram(attributes.HTTPClientRequestSize.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating http size histogram metric: %w", err)
		}
		m.httpClientRequestSize = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, httpClientRequestSize, mr.attrHTTPClientRequestSize, timeNow, mr.cfg.TTL)
	}

	if mr.is.GRPCEnabled() {
		grpcDuration, err := meter.Float64Histogram(attributes.RPCServerDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating grpc duration histogram metric: %w", err)
		}
		m.grpcDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, grpcDuration, mr.attrGRPCServer, timeNow, mr.cfg.TTL)

		grpcClientDuration, err := meter.Float64Histogram(attributes.RPCClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating grpc duration histogram metric: %w", err)
		}
		m.grpcClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, grpcClientDuration, mr.attrGRPCClient, timeNow, mr.cfg.TTL)
	}

	if mr.is.DBEnabled() {
		dbClientDuration, err := meter.Float64Histogram(attributes.DBClientDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating db client duration histogram metric: %w", err)
		}
		m.dbClientDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, dbClientDuration, mr.attrDBClient, timeNow, mr.cfg.TTL)
	}

	if mr.is.MQEnabled() {
		msgPublishDuration, err := meter.Float64Histogram(attributes.MessagingPublishDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating messaging client publish duration histogram metric: %w", err)
		}
		m.msgPublishDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, msgPublishDuration, mr.attrMessagingPublish, timeNow, mr.cfg.TTL)

		msgProcessDuration, err := meter.Float64Histogram(attributes.MessagingProcessDuration.OTEL, instrument.WithUnit("s"))
		if err != nil {
			return fmt.Errorf("creating messaging client process duration histogram metric: %w", err)
		}
		m.msgProcessDuration = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
			m.ctx, msgProcessDuration, mr.attrMessagingProcess, timeNow, mr.cfg.TTL)
	}

	if mr.is.GPUEnabled() {
		gpuKernelCallsTotal, err := meter.Int64Counter(attributes.GPUKernelLaunchCalls.OTEL)
		if err != nil {
			return fmt.Errorf("creating gpu kernel calls total: %w", err)
		}
		m.gpuKernelCallsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
			m.ctx, gpuKernelCallsTotal, mr.attrGPUKernelCalls, timeNow, mr.cfg.TTL)

		gpuMemoryAllocationsTotal, err := meter.Int64Counter(attributes.GPUMemoryAllocations.OTEL, instrument.WithUnit("By"))
		if err != nil {
			return fmt.Errorf("creating gpu memory allocations total: %w", err)
		}
		m.gpuMemoryAllocsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
			m.ctx, gpuMemoryAllocationsTotal, mr.attrGPUMemoryAllocations, timeNow, mr.cfg.TTL)
	}

	return nil
}

func (mr *MetricsReporter) setupSpanMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.SpanMetricsEnabled() {
		return nil
	}

	var err error

	spanMetricAttrs := mr.spanMetricAttributes()

	spanMetricsLatency, err := meter.Float64Histogram(SpanMetricsLatency)
	if err != nil {
		return fmt.Errorf("creating span metric histogram for latency: %w", err)
	}
	m.spanMetricsLatency = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, spanMetricsLatency, spanMetricAttrs, timeNow, mr.cfg.TTL)

	spanMetricsCallsTotal, err := meter.Int64Counter(SpanMetricsCalls)
	if err != nil {
		return fmt.Errorf("creating span metric calls total: %w", err)
	}
	m.spanMetricsCallsTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, spanMetricsCallsTotal, spanMetricAttrs, timeNow, mr.cfg.TTL)

	spanMetricsSizeTotal, err := meter.Float64Counter(SpanMetricsSizes)
	if err != nil {
		return fmt.Errorf("creating span metric size total: %w", err)
	}
	m.spanMetricsSizeTotal = NewExpirer[*request.Span, instrument.Float64Counter, float64](
		m.ctx, spanMetricsSizeTotal, spanMetricAttrs, timeNow, mr.cfg.TTL)

	m.tracesTargetInfo, err = meter.Int64UpDownCounter(TracesTargetInfo)
	if err != nil {
		return fmt.Errorf("creating span metric traces target info: %w", err)
	}

	return nil
}

func (mr *MetricsReporter) setupHostInfoMeter(meter instrument.Meter) error {
	tracesHostInfo, err := meter.Int64Gauge(TracesHostInfo)
	if err != nil {
		return fmt.Errorf("creating span metric traces host info: %w", err)
	}
	attrOpt := instrument.WithAttributeSet(mr.metricHostAttributes())
	tracesHostInfo.Record(mr.ctx, 1, attrOpt)

	return nil
}

func (mr *MetricsReporter) setupGraphMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.ServiceGraphMetricsEnabled() {
		return nil
	}

	var err error

	serviceGraphAttrs := mr.serviceGraphAttributes()

	serviceGraphClient, err := meter.Float64Histogram(ServiceGraphClient, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph client histogram: %w", err)
	}
	m.serviceGraphClient = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, serviceGraphClient, serviceGraphAttrs, timeNow, mr.cfg.TTL)

	serviceGraphServer, err := meter.Float64Histogram(ServiceGraphServer, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph server histogram: %w", err)
	}
	m.serviceGraphServer = NewExpirer[*request.Span, instrument.Float64Histogram, float64](
		m.ctx, serviceGraphServer, serviceGraphAttrs, timeNow, mr.cfg.TTL)

	serviceGraphFailed, err := meter.Int64Counter(ServiceGraphFailed)
	if err != nil {
		return fmt.Errorf("creating service graph failed total: %w", err)
	}
	m.serviceGraphFailed = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, serviceGraphFailed, serviceGraphAttrs, timeNow, mr.cfg.TTL)

	serviceGraphTotal, err := meter.Int64Counter(ServiceGraphTotal)
	if err != nil {
		return fmt.Errorf("creating service graph total: %w", err)
	}
	m.serviceGraphTotal = NewExpirer[*request.Span, instrument.Int64Counter, int64](
		m.ctx, serviceGraphTotal, serviceGraphAttrs, timeNow, mr.cfg.TTL)

	if m.tracesTargetInfo == nil {
		m.tracesTargetInfo, err = meter.Int64UpDownCounter(TracesTargetInfo)
		if err != nil {
			return fmt.Errorf("creating service graph traces target info: %w", err)
		}
	}

	return nil
}

func (mr *MetricsReporter) newMetricsInstance(service *svc.Attrs) Metrics {
	mlog := mlog()
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		mlog = mlog.With("service", service)
		resourceAttributes = append(getAppResourceAttrs(mr.hostID, service), ResourceAttrsFromEnv(service)...)
	}
	mlog.Debug("creating new Metrics reporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)

	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(mr.cfg.Interval))),
	}

	opts = append(opts, mr.otelMetricOptions(mlog)...)
	opts = append(opts, mr.spanMetricOptions(mlog)...)
	opts = append(opts, mr.graphMetricOptions(mlog)...)

	return Metrics{
		ctx:     mr.ctx,
		service: service,
		provider: metric.NewMeterProvider(
			opts...,
		),
	}
}

func (mr *MetricsReporter) newMetricSet(service *svc.Attrs) (*Metrics, error) {
	m := mr.newMetricsInstance(service)

	// time units for HTTP and GRPC durations are in seconds, according to the OTEL specification:
	// https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/metrics/semantic_conventions
	// TODO: set ExplicitBucketBoundaries here and in prometheus from the previous specification
	meter := m.provider.Meter(reporterName)
	var err error
	if mr.cfg.OTelMetricsEnabled() {
		err = mr.setupOtelMeters(&m, meter)
		if err != nil {
			return nil, err
		}
	}

	if mr.cfg.SpanMetricsEnabled() {
		err = mr.setupSpanMeters(&m, meter)
		if err != nil {
			return nil, err
		}
		attrOpt := instrument.WithAttributeSet(mr.metricResourceAttributes(service))
		m.tracesTargetInfo.Add(mr.ctx, 1, attrOpt)
	}

	if mr.cfg.ServiceGraphMetricsEnabled() {
		err = mr.setupGraphMeters(&m, meter)
		if err != nil {
			return nil, err
		}
		attrOpt := instrument.WithAttributeSet(mr.metricResourceAttributes(service))
		m.tracesTargetInfo.Add(mr.ctx, 1, attrOpt)
	}

	return &m, nil
}

func isExponentialAggregation(mc *MetricsConfig, mlog *slog.Logger) bool {
	switch mc.HistogramAggregation {
	case AggregationExponential:
		return true
	case AggregationExplicit:
	// do nothing
	default:
		mlog.Warn("invalid value for histogram aggregation. Accepted values are: "+
			AggregationExponential+", "+AggregationExplicit+" (default). Using default",
			"value", mc.HistogramAggregation)
	}
	return false
}

func InstantiateMetricsExporter(ctx context.Context, cfg *MetricsConfig, log *slog.Logger) (sdkmetric.Exporter, error) {
	var err error
	var exporter sdkmetric.Exporter
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		log.Debug("instantiating HTTP MetricsReporter", "protocol", proto)
		if exporter, err = httpMetricsExporter(ctx, cfg); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL HTTP metrics exporter: %w", err)
		}
	case ProtocolGRPC:
		log.Debug("instantiating GRPC MetricsReporter", "protocol", proto)
		if exporter, err = grpcMetricsExporter(ctx, cfg); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL GRPC metrics exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
	}
	return exporter, nil
}

func httpMetricsExporter(ctx context.Context, cfg *MetricsConfig) (sdkmetric.Exporter, error) {
	opts, err := getHTTPMetricEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetrichttp.New(ctx, opts.AsMetricHTTP()...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP metric exporter: %w", err)
	}
	return mexp, nil
}

func grpcMetricsExporter(ctx context.Context, cfg *MetricsConfig) (sdkmetric.Exporter, error) {
	opts, err := getGRPCMetricEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetricgrpc.New(ctx, opts.AsMetricGRPC()...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC metric exporter: %w", err)
	}
	return mexp, nil
}

func (mr *MetricsReporter) close() {
	if err := mr.exporter.Shutdown(mr.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", "error", err)
	}
}

// instrumentMetricsExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed metrics exporter inside an instrumented exporter
func instrumentMetricsExporter(internalMetrics imetrics.Reporter, in sdkmetric.Exporter) sdkmetric.Exporter {
	// avoid wrapping the instrumented exporter if we don't have
	// internal instrumentation (NoopReporter)
	if _, ok := internalMetrics.(imetrics.NoopReporter); ok || internalMetrics == nil {
		return in
	}
	return &instrumentedMetricsExporter{
		Exporter: in,
		internal: internalMetrics,
	}
}

func otelHistogramConfig(metricName string, buckets []float64, useExponentialHistogram bool) metric.View {
	if useExponentialHistogram {
		return metric.NewView(
			metric.Instrument{
				Name:  metricName,
				Scope: instrumentation.Scope{Name: reporterName},
			},
			metric.Stream{
				Name: metricName,
				Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{
					MaxScale: 20,
					MaxSize:  160,
				},
			})
	}
	return metric.NewView(
		metric.Instrument{
			Name:  metricName,
			Scope: instrumentation.Scope{Name: reporterName},
		},
		metric.Stream{
			Name: metricName,
			Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
				Boundaries: buckets,
			},
		})

}

func (mr *MetricsReporter) metricResourceAttributes(service *svc.Attrs) attribute.Set {
	attrs := []attribute.KeyValue{
		request.ServiceMetric(service.UID.Name),
		semconv.ServiceInstanceID(service.UID.Instance),
		semconv.ServiceNamespace(service.UID.Namespace),
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		semconv.TelemetrySDKNameKey.String("beyla"),
		request.SourceMetric("beyla"),
		semconv.HostID(mr.hostID),
	}
	for k, v := range service.Metadata {
		attrs = append(attrs, k.OTEL().String(v))
	}

	return attribute.NewSet(attrs...)
}

func (mr *MetricsReporter) metricHostAttributes() attribute.Set {
	attrs := []attribute.KeyValue{
		GrafanaHostIDKey.String(mr.hostID),
	}

	return attribute.NewSet(attrs...)
}

// spanMetricAttributes follow a given specification, so their attribute getters are predefined and can't be
// selected by the user
func (mr *MetricsReporter) spanMetricAttributes() []attributes.Field[*request.Span, attribute.KeyValue] {
	return append(attributes.OpenTelemetryGetters(
		request.SpanOTELGetters, []attr.Name{
			attr.Service,
			attr.ServiceInstanceID,
			attr.ServiceNamespace,
			attr.SpanKind,
			attr.SpanName,
			attr.StatusCode,
			attr.Source,
		}),
		// hostID is not taken from the span but common to the metrics reporter,
		// so the getter is injected here directly
		attributes.Field[*request.Span, attribute.KeyValue]{
			ExposedName: string(attr.HostID.OTEL()),
			Get: func(_ *request.Span) attribute.KeyValue {
				return semconv.HostID(mr.hostID)
			},
		})
}

func (mr *MetricsReporter) serviceGraphAttributes() []attributes.Field[*request.Span, attribute.KeyValue] {
	return attributes.OpenTelemetryGetters(
		request.SpanOTELGetters, []attr.Name{
			attr.Client,
			attr.ClientNamespace,
			attr.Server,
			attr.ServerNamespace,
			attr.Source,
		})
}

func otelSpanAccepted(span *request.Span, mr *MetricsReporter) bool {
	return mr.cfg.OTelMetricsEnabled() && !span.Service.ExportsOTelMetrics()
}

// nolint:cyclop
func (r *Metrics) record(span *request.Span, mr *MetricsReporter) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()

	ctx := trace.ContextWithSpanContext(r.ctx, trace.SpanContext{}.WithTraceID(span.TraceID).WithSpanID(span.SpanID).WithTraceFlags(trace.TraceFlags(span.Flags)))

	if otelSpanAccepted(span, mr) {
		switch span.Type {
		case request.EventTypeHTTP:
			if mr.is.HTTPEnabled() {
				// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
				httpDuration, attrs := r.httpDuration.ForRecord(span)
				httpDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))

				httpRequestSize, attrs := r.httpRequestSize.ForRecord(span)
				httpRequestSize.Record(ctx, float64(span.RequestLength()), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPC:
			if mr.is.GRPCEnabled() {
				grpcDuration, attrs := r.grpcDuration.ForRecord(span)
				grpcDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPCClient:
			if mr.is.GRPCEnabled() {
				grpcClientDuration, attrs := r.grpcClientDuration.ForRecord(span)
				grpcClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeHTTPClient:
			if mr.is.HTTPEnabled() {
				httpClientDuration, attrs := r.httpClientDuration.ForRecord(span)
				httpClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				httpClientRequestSize, attrs := r.httpClientRequestSize.ForRecord(span)
				httpClientRequestSize.Record(ctx, float64(span.RequestLength()), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeRedisServer, request.EventTypeRedisClient, request.EventTypeSQLClient:
			if mr.is.DBEnabled() {
				dbClientDuration, attrs := r.dbClientDuration.ForRecord(span)
				dbClientDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if mr.is.MQEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					msgPublishDuration, attrs := r.msgPublishDuration.ForRecord(span)
					msgPublishDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				case request.MessagingProcess:
					msgProcessDuration, attrs := r.msgProcessDuration.ForRecord(span)
					msgProcessDuration.Record(ctx, duration, instrument.WithAttributeSet(attrs))
				}
			}
		case request.EventTypeGPUKernelLaunch:
			if mr.is.GPUEnabled() {
				gcalls, attrs := r.gpuKernelCallsTotal.ForRecord(span)
				gcalls.Add(ctx, 1, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGPUMalloc:
			if mr.is.GPUEnabled() {
				gmem, attrs := r.gpuMemoryAllocsTotal.ForRecord(span)
				gmem.Add(ctx, span.ContentLength, instrument.WithAttributeSet(attrs))
			}
		}
	}

	if mr.cfg.SpanMetricsEnabled() {
		sml, attrs := r.spanMetricsLatency.ForRecord(span)
		sml.Record(ctx, duration, instrument.WithAttributeSet(attrs))

		smct, attrs := r.spanMetricsCallsTotal.ForRecord(span)
		smct.Add(ctx, 1, instrument.WithAttributeSet(attrs))

		smst, attrs := r.spanMetricsSizeTotal.ForRecord(span)
		smst.Add(ctx, float64(span.RequestLength()), instrument.WithAttributeSet(attrs))
	}

	if mr.cfg.ServiceGraphMetricsEnabled() {
		if !span.IsSelfReferenceSpan() || mr.cfg.AllowServiceGraphSelfReferences {
			if span.IsClientSpan() {
				sgc, attrs := r.serviceGraphClient.ForRecord(span)
				sgc.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			} else {
				sgs, attrs := r.serviceGraphServer.ForRecord(span)
				sgs.Record(ctx, duration, instrument.WithAttributeSet(attrs))
			}
			sgt, attrs := r.serviceGraphTotal.ForRecord(span)
			sgt.Add(ctx, 1, instrument.WithAttributeSet(attrs))
			if request.SpanStatusCode(span) == codes.Error {
				sgf, attrs := r.serviceGraphFailed.ForRecord(span)
				sgf.Add(ctx, 1, instrument.WithAttributeSet(attrs))
			}
		}
	}
}

func (mr *MetricsReporter) reportMetrics(input <-chan []request.Span) {
	for spans := range input {
		for i := range spans {
			s := &spans[i]
			if s.InternalSignal() {
				continue
			}
			// If we are ignoring this span because of route patterns, don't do anything
			if s.IgnoreMetrics() {
				continue
			}
			reporter, err := mr.reporters.For(&s.Service)
			if err != nil {
				mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
					"error", err, "service", s.Service)
				continue
			}
			reporter.record(s, mr)
		}
	}
	mr.close()
}

func getHTTPMetricEndpointOptions(cfg *MetricsConfig) (otlpOptions, error) {
	opts := otlpOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "http")
	murl, isCommon, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/metrics to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = murl.Path
	if isCommon {
		if strings.HasSuffix(opts.URLPath, "/") {
			opts.URLPath += "v1/metrics"
		} else {
			opts.URLPath += "/v1/metrics"
		}
	}
	log.Debug("Specifying path", "path", opts.URLPath)

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = cfg.InsecureSkipVerify
	}

	cfg.Grafana.setupOptions(&opts)
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

func getGRPCMetricEndpointOptions(cfg *MetricsConfig) (otlpOptions, error) {
	opts := otlpOptions{Headers: map[string]string{}}
	log := mlog().With("transport", "grpc")
	murl, _, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return opts, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	cfg.Grafana.setupOptions(&opts)
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envMetricsHeaders))

	return opts, nil
}

// the HTTP path will be defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
func parseMetricsEndpoint(cfg *MetricsConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPMetricsEndpoint()

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

// HACK: at the time of writing this, the otelpmetrichttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelpmetrichttp.WithProtocol is supported
func setMetricsProtocol(cfg *MetricsConfig) {
	if _, ok := os.LookupEnv(envMetricsProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.MetricsProtocol != "" {
		os.Setenv(envMetricsProtocol, string(cfg.MetricsProtocol))
		return
	}
	if cfg.Protocol != "" {
		os.Setenv(envProtocol, string(cfg.Protocol))
		return
	}
	// unset. Guessing it
	os.Setenv(envMetricsProtocol, string(cfg.GuessProtocol()))
}

func cleanupMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Float64Histogram, float64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func cleanupCounterMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Int64Counter, int64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func cleanupFloatCounterMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Float64Counter, float64]) {
	if m != nil {
		m.RemoveAllMetrics(ctx)
	}
}

func (r *Metrics) cleanupAllMetricsInstances() {
	cleanupMetrics(r.ctx, r.httpDuration)
	cleanupMetrics(r.ctx, r.httpClientDuration)
	cleanupMetrics(r.ctx, r.grpcDuration)
	cleanupMetrics(r.ctx, r.grpcClientDuration)
	cleanupMetrics(r.ctx, r.dbClientDuration)
	cleanupMetrics(r.ctx, r.msgPublishDuration)
	cleanupMetrics(r.ctx, r.msgProcessDuration)
	cleanupMetrics(r.ctx, r.httpRequestSize)
	cleanupMetrics(r.ctx, r.httpClientRequestSize)
	cleanupMetrics(r.ctx, r.spanMetricsLatency)
	cleanupCounterMetrics(r.ctx, r.spanMetricsCallsTotal)
	cleanupFloatCounterMetrics(r.ctx, r.spanMetricsSizeTotal)
	cleanupMetrics(r.ctx, r.serviceGraphClient)
	cleanupMetrics(r.ctx, r.serviceGraphServer)
	cleanupCounterMetrics(r.ctx, r.serviceGraphFailed)
	cleanupCounterMetrics(r.ctx, r.serviceGraphTotal)
	cleanupCounterMetrics(r.ctx, r.gpuKernelCallsTotal)
}
