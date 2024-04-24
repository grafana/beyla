package otel

import (
	"context"
	"fmt"
	"log/slog"
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
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attr"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

const (
	HTTPServerDuration    = attr.SectionHTTPServerDuration
	HTTPClientDuration    = attr.SectionHTTPClientDuration
	RPCServerDuration     = attr.SectionRPCServerDuration
	RPCClientDuration     = attr.SectionRPCClientDuration
	SQLClientDuration     = attr.SectionSQLClientDuration
	HTTPServerRequestSize = attr.SectionHTTPServerRequestSize
	HTTPClientRequestSize = attr.SectionHTTPClientRequestSize
	SpanMetricsLatency    = "traces_spanmetrics_latency"
	SpanMetricsCalls      = "traces_spanmetrics_calls_total"
	SpanMetricsSizes      = "traces_spanmetrics_size_total"
	TracesTargetInfo      = "traces_target_info"
	ServiceGraphClient    = "traces_service_graph_request_client"
	ServiceGraphServer    = "traces_service_graph_request_server"
	ServiceGraphFailed    = "traces_service_graph_request_failed_total"
	ServiceGraphTotal     = "traces_service_graph_request_total"

	UsualPortGRPC = "4317"
	UsualPortHTTP = "4318"

	AggregationExplicit    = "explicit_bucket_histogram"
	AggregationExponential = "base2_exponential_bucket_histogram"

	FeatureNetwork     = "network"
	FeatureApplication = "application"
	FeatureSpan        = "application_span"
	FeatureGraph       = "application_service_graph"
)

type MetricsConfig struct {
	Interval time.Duration `yaml:"interval" env:"BEYLA_METRICS_INTERVAL"`

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

	// TTL is the time since a metric was updated for the last time until it is
	// removed from the metrics set.
	TTL time.Duration `yaml:"ttl" env:"BEYLA_OTEL_METRICS_TTL"`

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

// EndpointEnabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
// nolint:gocritic
func (m MetricsConfig) EndpointEnabled() bool {
	return m.CommonEndpoint != "" || m.MetricsEndpoint != "" || m.Grafana.MetricsEnabled()
}

func (m MetricsConfig) SpanMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureSpan)
}

func (m MetricsConfig) ServiceGraphMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureGraph)
}

func (m MetricsConfig) OTelMetricsEnabled() bool {
	return slices.Contains(m.Features, FeatureApplication)
}

func (m MetricsConfig) Enabled() bool {
	return m.EndpointEnabled() && (m.OTelMetricsEnabled() || m.SpanMetricsEnabled() || m.ServiceGraphMetricsEnabled())
}

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx       context.Context
	cfg       *MetricsConfig
	allowed   attr.AllowedAttributesDefinition
	exporter  metric.Exporter
	reporters ReporterPool[*Metrics]
}

// Metrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by Beyla.
type Metrics struct {
	ctx      context.Context
	service  svc.ID
	provider *metric.MeterProvider

	attrHTTPDuration          []attr.Getter[*request.Span, attribute.KeyValue]
	attrHTTPClientDuration    []attr.Getter[*request.Span, attribute.KeyValue]
	attrGRPCServer            []attr.Getter[*request.Span, attribute.KeyValue]
	attrGRPCClient            []attr.Getter[*request.Span, attribute.KeyValue]
	attrSQLClient             []attr.Getter[*request.Span, attribute.KeyValue]
	attrHTTPRequestSize       []attr.Getter[*request.Span, attribute.KeyValue]
	attrHTTPClientRequestSize []attr.Getter[*request.Span, attribute.KeyValue]

	httpDuration          instrument.Float64Histogram
	httpClientDuration    instrument.Float64Histogram
	grpcDuration          instrument.Float64Histogram
	grpcClientDuration    instrument.Float64Histogram
	sqlClientDuration     instrument.Float64Histogram
	httpRequestSize       instrument.Float64Histogram
	httpClientRequestSize instrument.Float64Histogram
	// trace span metrics
	spanMetricsLatency    instrument.Float64Histogram
	spanMetricsCallsTotal instrument.Int64Counter
	spanMetricsSizeTotal  instrument.Float64Counter
	tracesTargetInfo      instrument.Int64UpDownCounter
	serviceGraphClient    instrument.Float64Histogram
	serviceGraphServer    instrument.Float64Histogram
	serviceGraphFailed    instrument.Int64Counter
	serviceGraphTotal     instrument.Int64Counter
}

func ReportMetrics(
	ctx context.Context, cfg *MetricsConfig, ctxInfo *global.ContextInfo,
) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !cfg.Enabled() {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		mr, err := newMetricsReporter(ctx, cfg, ctxInfo)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
		}
		return mr.reportMetrics, nil
	}
}

func newMetricsReporter(ctx context.Context, cfg *MetricsConfig, ctxInfo *global.ContextInfo) (*MetricsReporter, error) {
	log := mlog()
	mr := MetricsReporter{
		ctx: ctx,
		cfg: cfg,
	}
	mr.reporters = NewReporterPool[*Metrics](cfg.ReportersCacheLen,
		func(id svc.UID, v *Metrics) {
			if mr.cfg.SpanMetricsEnabled() {
				attrOpt := instrument.WithAttributeSet(mr.metricResourceAttributes(v.service))
				v.tracesTargetInfo.Add(mr.ctx, 1, attrOpt)
			}

			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
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
	if !mr.cfg.OTelMetricsEnabled() {
		return []metric.Option{}
	}

	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)

	return []metric.Option{
		metric.WithView(otelHistogramConfig(HTTPServerDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(HTTPClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(RPCServerDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(RPCClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(SQLClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(HTTPServerRequestSize, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
		metric.WithView(otelHistogramConfig(HTTPClientRequestSize, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
	}
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

func (mr *MetricsReporter) setupOtelMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.OTelMetricsEnabled() {
		return nil
	}

	m.attrHTTPDuration = attr.OpenTelemetryGetters(
		HttpServerAttributes, mr.allowed.For(HTTPServerDuration))
	m.attrHTTPClientDuration = attr.OpenTelemetryGetters(
		HttpClientAttributes, mr.allowed.For(HTTPClientDuration))
	m.attrHTTPRequestSize = attr.OpenTelemetryGetters(
		HttpServerAttributes, mr.allowed.For(HTTPServerRequestSize))
	m.attrHTTPClientRequestSize = attr.OpenTelemetryGetters(
		HttpClientAttributes, mr.allowed.For(HTTPClientRequestSize))
	m.attrGRPCServer = attr.OpenTelemetryGetters(
		GRPCServerAttributes, mr.allowed.For(RPCServerDuration))
	m.attrGRPCClient = attr.OpenTelemetryGetters(
		GRPCClientAttributes, mr.allowed.For(RPCClientDuration))
	m.attrSQLClient = attr.OpenTelemetryGetters(
		SQLAttributes, mr.allowed.For(SQLClientDuration))

	var err error
	m.httpDuration, err = meter.Float64Histogram(HTTPServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	m.httpClientDuration, err = meter.Float64Histogram(HTTPClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	m.grpcDuration, err = meter.Float64Histogram(RPCServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	m.grpcClientDuration, err = meter.Float64Histogram(RPCClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	m.sqlClientDuration, err = meter.Float64Histogram(SQLClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating sql client duration histogram metric: %w", err)
	}
	m.httpRequestSize, err = meter.Float64Histogram(HTTPServerRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating http size histogram metric: %w", err)
	}
	m.httpClientRequestSize, err = meter.Float64Histogram(HTTPClientRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating http size histogram metric: %w", err)
	}

	return nil
}

func (mr *MetricsReporter) setupSpanMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.SpanMetricsEnabled() {
		return nil
	}

	var err error

	m.spanMetricsLatency, err = meter.Float64Histogram(SpanMetricsLatency)
	if err != nil {
		return fmt.Errorf("creating span metric histogram for latency: %w", err)
	}

	m.spanMetricsCallsTotal, err = meter.Int64Counter(SpanMetricsCalls)
	if err != nil {
		return fmt.Errorf("creating span metric calls total: %w", err)
	}

	m.spanMetricsSizeTotal, err = meter.Float64Counter(SpanMetricsSizes)
	if err != nil {
		return fmt.Errorf("creating span metric size total: %w", err)
	}

	m.tracesTargetInfo, err = meter.Int64UpDownCounter(TracesTargetInfo)
	if err != nil {
		return fmt.Errorf("creating span metric traces target info: %w", err)
	}

	return nil
}

func (mr *MetricsReporter) setupGraphMeters(m *Metrics, meter instrument.Meter) error {
	if !mr.cfg.ServiceGraphMetricsEnabled() {
		return nil
	}

	var err error

	m.serviceGraphClient, err = meter.Float64Histogram(ServiceGraphClient, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph client histogram: %w", err)
	}

	m.serviceGraphServer, err = meter.Float64Histogram(ServiceGraphServer, instrument.WithUnit("s"))
	if err != nil {
		return fmt.Errorf("creating service graph server histogram: %w", err)
	}

	m.serviceGraphFailed, err = meter.Int64Counter(ServiceGraphFailed)
	if err != nil {
		return fmt.Errorf("creating service graph failed total: %w", err)
	}

	m.serviceGraphTotal, err = meter.Int64Counter(ServiceGraphTotal)
	if err != nil {
		return fmt.Errorf("creating service graph total: %w", err)
	}

	return nil
}

func (mr *MetricsReporter) newMetricSet(service svc.ID) (*Metrics, error) {
	mlog := mlog().With("service", service)
	mlog.Debug("creating new Metrics reporter")
	resources := Resource(service)

	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(mr.cfg.Interval))),
	}

	opts = append(opts, mr.otelMetricOptions(mlog)...)
	opts = append(opts, mr.spanMetricOptions(mlog)...)
	opts = append(opts, mr.graphMetricOptions(mlog)...)

	m := Metrics{
		ctx:     mr.ctx,
		service: service,
		provider: metric.NewMeterProvider(
			opts...,
		),
	}
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

// TODO: restore as private
func InstantiateMetricsExporter(ctx context.Context, cfg *MetricsConfig, log *slog.Logger) (metric.Exporter, error) {
	var err error
	var exporter metric.Exporter
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

func httpMetricsExporter(ctx context.Context, cfg *MetricsConfig) (metric.Exporter, error) {
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

func grpcMetricsExporter(ctx context.Context, cfg *MetricsConfig) (metric.Exporter, error) {
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
func instrumentMetricsExporter(internalMetrics imetrics.Reporter, in metric.Exporter) metric.Exporter {
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
				Aggregation: metric.AggregationBase2ExponentialHistogram{
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
			Aggregation: metric.AggregationExplicitBucketHistogram{
				Boundaries: buckets,
			},
		})

}

func (mr *MetricsReporter) metricResourceAttributes(service svc.ID) attribute.Set {
	attrs := []attribute.KeyValue{
		ServiceMetric(service.Name),
		semconv.ServiceInstanceID(service.Instance),
		semconv.ServiceNamespace(service.Namespace),
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		semconv.TelemetrySDKNameKey.String("beyla"),
		SourceMetric("beyla"),
	}
	for k, v := range service.Metadata {
		attrs = append(attrs, attribute.String(k, v))
	}

	return attribute.NewSet(attrs...)
}

func (mr *MetricsReporter) spanMetricAttributes(span *request.Span) attribute.Set {
	attrs := []attribute.KeyValue{
		ServiceMetric(span.ServiceID.Name),
		semconv.ServiceInstanceID(span.ServiceID.Instance),
		semconv.ServiceNamespace(span.ServiceID.Namespace),
		SpanKindMetric(SpanKindString(span)),
		SpanNameMetric(TraceName(span)),
		StatusCodeMetric(int(SpanStatusCode(span))),
		SourceMetric("beyla"),
	}

	return attribute.NewSet(attrs...)
}

func (mr *MetricsReporter) serviceGraphAttributes(span *request.Span) attribute.Set {
	var attrs []attribute.KeyValue
	if span.IsClientSpan() {
		attrs = []attribute.KeyValue{
			ClientMetric(SpanPeer(span)),
			ClientNamespaceMetric(span.ServiceID.Namespace),
			ServerMetric(SpanHost(span)),
			ServerNamespaceMetric(span.OtherNamespace),
			ConnectionTypeMetric("virtual_node"),
			SourceMetric("beyla"),
		}
	} else {
		attrs = []attribute.KeyValue{
			ClientMetric(SpanPeer(span)),
			ClientNamespaceMetric(span.OtherNamespace),
			ServerMetric(SpanHost(span)),
			ServerNamespaceMetric(span.ServiceID.Namespace),
			ConnectionTypeMetric("virtual_node"),
			SourceMetric("beyla"),
		}
	}
	return attribute.NewSet(attrs...)
}

func withAttributes(span *request.Span, getters []attr.Getter[*request.Span, attribute.KeyValue]) instrument.MeasurementOption {
	attributes := make([]attribute.KeyValue, 0, len(getters))
	for _, get := range getters {
		attributes = append(attributes, get.Get(span))
	}
	return instrument.WithAttributeSet(attribute.NewSet(attributes...))
}

func (r *Metrics) record(span *request.Span, mr *MetricsReporter) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()

	if mr.cfg.OTelMetricsEnabled() {
		switch span.Type {
		case request.EventTypeHTTP:
			// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
			r.httpDuration.Record(r.ctx, duration,
				withAttributes(span, r.attrHTTPDuration))
			r.httpRequestSize.Record(r.ctx, float64(span.ContentLength),
				withAttributes(span, r.attrHTTPRequestSize))
		case request.EventTypeGRPC:
			r.grpcDuration.Record(r.ctx, duration,
				withAttributes(span, r.attrGRPCServer))
		case request.EventTypeGRPCClient:
			r.grpcClientDuration.Record(r.ctx, duration,
				withAttributes(span, r.attrGRPCClient))
		case request.EventTypeHTTPClient:
			r.httpClientDuration.Record(r.ctx, duration,
				withAttributes(span, r.attrHTTPClientDuration))
			r.httpClientRequestSize.Record(r.ctx, float64(span.ContentLength),
				withAttributes(span, r.attrHTTPClientRequestSize))
		case request.EventTypeSQLClient:
			r.sqlClientDuration.Record(r.ctx, duration,
				withAttributes(span, r.attrSQLClient))
		}
	}

	if mr.cfg.SpanMetricsEnabled() {
		attrOpt := instrument.WithAttributeSet(mr.spanMetricAttributes(span))
		r.spanMetricsLatency.Record(r.ctx, duration, attrOpt)
		r.spanMetricsCallsTotal.Add(r.ctx, 1, attrOpt)
		r.spanMetricsSizeTotal.Add(r.ctx, float64(span.ContentLength), attrOpt)
	}

	if mr.cfg.ServiceGraphMetricsEnabled() {
		attrOpt := instrument.WithAttributeSet(mr.serviceGraphAttributes(span))
		if span.IsClientSpan() {
			r.serviceGraphClient.Record(r.ctx, duration, attrOpt)
		} else {
			r.serviceGraphServer.Record(r.ctx, duration, attrOpt)
		}
		r.serviceGraphTotal.Add(r.ctx, 1, attrOpt)
		if SpanStatusCode(span) == codes.Error {
			r.serviceGraphFailed.Add(r.ctx, 1, attrOpt)
		}
	}
}

func (mr *MetricsReporter) reportMetrics(input <-chan []request.Span) {
	var lastSvcUID svc.UID
	var reporter *Metrics
	for spans := range input {
		for i := range spans {
			s := &spans[i]

			// If we are ignoring this span because of route patterns, don't do anything
			if s.IgnoreSpan == request.IgnoreMetrics {
				continue
			}

			// optimization: do not query the resources' cache if the
			// previously processed span belongs to the same service name
			// as the current.
			// This will save querying OTEL resource reporters when there is
			// only a single instrumented process.
			// In multi-process tracing, this is likely to happen as most
			// tracers group traces belonging to the same service in the same slice.
			if s.ServiceID.UID != lastSvcUID || reporter == nil {
				lm, err := mr.reporters.For(s.ServiceID)
				if err != nil {
					mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
						err, "service", s.ServiceID)
					continue
				}
				lastSvcUID = s.ServiceID.UID
				reporter = lm
			}
			reporter.record(s, mr)
		}
	}
	mr.close()
}

func getHTTPMetricEndpointOptions(cfg *MetricsConfig) (otlpOptions, error) {
	opts := otlpOptions{}
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

	return opts, nil
}

func getGRPCMetricEndpointOptions(cfg *MetricsConfig) (otlpOptions, error) {
	opts := otlpOptions{}
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
	return opts, nil
}

// the HTTP path will be defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
func parseMetricsEndpoint(cfg *MetricsConfig) (*url.URL, bool, error) {
	isCommon := false
	endpoint := cfg.MetricsEndpoint
	if endpoint == "" {
		isCommon = true
		endpoint = cfg.CommonEndpoint
		if endpoint == "" && cfg.Grafana != nil && cfg.Grafana.CloudZone != "" {
			endpoint = cfg.Grafana.Endpoint()
		}
	}

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
