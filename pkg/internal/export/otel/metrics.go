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

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/instrumentations"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
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
	ServiceGraphClient = "traces_service_graph_request_client"
	ServiceGraphServer = "traces_service_graph_request_server"
	ServiceGraphFailed = "traces_service_graph_request_failed_total"
	ServiceGraphTotal  = "traces_service_graph_request_total"

	UsualPortGRPC = "4317"
	UsualPortHTTP = "4318"

	AggregationExplicit    = "explicit_bucket_histogram"
	AggregationExponential = "base2_exponential_bucket_histogram"

	FeatureNetwork     = "network"
	FeatureApplication = "application"
	FeatureSpan        = "application_span"
	FeatureGraph       = "application_service_graph"
	FeatureProcess     = "application_process"
)

type MetricsConfig struct {
	Interval time.Duration `yaml:"interval" env:"BEYLA_METRICS_INTERVAL"`

	CommonEndpoint  string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	Protocol        Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	MetricsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"BEYLA_OTEL_INSECURE_SKIP_VERIFY"`

	// ReportTarget specifies whether http.target should be submitted as a metric attribute. It is disabled by
	// default to avoid cardinality explosion in paths with IDs. In that case, it is recommended to group these
	// requests in the Routes node
	// Deprecated. Going to be removed in Beyla 2.0. Use attributes.select instead
	ReportTarget bool `yaml:"report_target" env:"BEYLA_METRICS_REPORT_TARGET"`
	// Deprecated. Going to be removed in Beyla 2.0. Use attributes.select instead
	ReportPeerInfo bool `yaml:"report_peer" env:"BEYLA_METRICS_REPORT_PEER"`

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

func (m *MetricsConfig) Enabled() bool {
	return m.EndpointEnabled() && (m.OTelMetricsEnabled() || m.SpanMetricsEnabled() || m.ServiceGraphMetricsEnabled())
}

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx        context.Context
	cfg        *MetricsConfig
	attributes *attributes.AttrSelector
	exporter   metric.Exporter
	reporters  ReporterPool[*Metrics]
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
}

// Metrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by Beyla.
type Metrics struct {
	ctx      context.Context
	service  *svc.ID
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

	mr.reporters = NewReporterPool(cfg.ReportersCacheLen, cfg.TTL, timeNow,
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

	if m.tracesTargetInfo == nil {
		m.tracesTargetInfo, err = meter.Int64UpDownCounter(TracesTargetInfo)
		if err != nil {
			return fmt.Errorf("creating service graph traces target info: %w", err)
		}
	}

	return nil
}

func (mr *MetricsReporter) newMetricSet(service *svc.ID) (*Metrics, error) {
	mlog := mlog().With("service", service)
	mlog.Debug("creating new Metrics reporter")
	resources := getResourceAttrs(service)

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

func (mr *MetricsReporter) metricResourceAttributes(service *svc.ID) attribute.Set {
	attrs := []attribute.KeyValue{
		request.ServiceMetric(service.Name),
		semconv.ServiceInstanceID(service.Instance),
		semconv.ServiceNamespace(service.Namespace),
		semconv.TelemetrySDKLanguageKey.String(service.SDKLanguage.String()),
		semconv.TelemetrySDKNameKey.String("beyla"),
		request.SourceMetric("beyla"),
	}
	for k, v := range service.Metadata {
		attrs = append(attrs, k.OTEL().String(v))
	}

	return attribute.NewSet(attrs...)
}

func (mr *MetricsReporter) spanMetricAttributes(span *request.Span) attribute.Set {
	attrs := []attribute.KeyValue{
		request.ServiceMetric(span.ServiceID.Name),
		semconv.ServiceInstanceID(span.ServiceID.Instance),
		semconv.ServiceNamespace(span.ServiceID.Namespace),
		request.SpanKindMetric(SpanKindString(span)),
		request.SpanNameMetric(TraceName(span)),
		request.StatusCodeMetric(int(request.SpanStatusCode(span))),
		request.SourceMetric("beyla"),
	}

	return attribute.NewSet(attrs...)
}

func (mr *MetricsReporter) serviceGraphAttributes(span *request.Span) attribute.Set {
	var attrs []attribute.KeyValue
	if span.IsClientSpan() {
		attrs = []attribute.KeyValue{
			request.ClientMetric(request.SpanPeer(span)),
			request.ClientNamespaceMetric(span.ServiceID.Namespace),
			request.ServerMetric(request.SpanHost(span)),
			request.ServerNamespaceMetric(span.OtherNamespace),
			request.SourceMetric("beyla"),
		}
	} else {
		attrs = []attribute.KeyValue{
			request.ClientMetric(request.SpanPeer(span)),
			request.ClientNamespaceMetric(span.OtherNamespace),
			request.ServerMetric(request.SpanHost(span)),
			request.ServerNamespaceMetric(span.ServiceID.Namespace),
			request.SourceMetric("beyla"),
		}
	}
	return attribute.NewSet(attrs...)
}

// nolint:cyclop
func (r *Metrics) record(span *request.Span, mr *MetricsReporter) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()

	if mr.cfg.OTelMetricsEnabled() {
		switch span.Type {
		case request.EventTypeHTTP:
			if mr.is.HTTPEnabled() {
				// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
				httpDuration, attrs := r.httpDuration.ForRecord(span)
				httpDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))

				httpRequestSize, attrs := r.httpRequestSize.ForRecord(span)
				httpRequestSize.Record(r.ctx, float64(span.ContentLength), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPC:
			if mr.is.GRPCEnabled() {
				grpcDuration, attrs := r.grpcDuration.ForRecord(span)
				grpcDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeGRPCClient:
			if mr.is.GRPCEnabled() {
				grpcClientDuration, attrs := r.grpcClientDuration.ForRecord(span)
				grpcClientDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeHTTPClient:
			if mr.is.HTTPEnabled() {
				httpClientDuration, attrs := r.httpClientDuration.ForRecord(span)
				httpClientDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
				httpClientRequestSize, attrs := r.httpClientRequestSize.ForRecord(span)
				httpClientRequestSize.Record(r.ctx, float64(span.ContentLength), instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeRedisServer, request.EventTypeRedisClient, request.EventTypeSQLClient:
			if mr.is.DBEnabled() {
				dbClientDuration, attrs := r.dbClientDuration.ForRecord(span)
				dbClientDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
			}
		case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
			if mr.is.MQEnabled() {
				switch span.Method {
				case request.MessagingPublish:
					msgPublishDuration, attrs := r.msgPublishDuration.ForRecord(span)
					msgPublishDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
				case request.MessagingProcess:
					msgProcessDuration, attrs := r.msgProcessDuration.ForRecord(span)
					msgProcessDuration.Record(r.ctx, duration, instrument.WithAttributeSet(attrs))
				}
			}
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
		if request.SpanStatusCode(span) == codes.Error {
			r.serviceGraphFailed.Add(r.ctx, 1, attrOpt)
		}
	}
}

func (mr *MetricsReporter) reportMetrics(input <-chan []request.Span) {
	for spans := range input {
		for i := range spans {
			s := &spans[i]

			// If we are ignoring this span because of route patterns, don't do anything
			if s.IgnoreSpan == request.IgnoreMetrics {
				continue
			}
			reporter, err := mr.reporters.For(&s.ServiceID)
			if err != nil {
				mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
					err, "service", s.ServiceID)
				continue
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

func cleanupMetrics(ctx context.Context, m *Expirer[*request.Span, instrument.Float64Histogram, float64]) {
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
}
