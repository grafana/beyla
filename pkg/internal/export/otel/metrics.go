package otel

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

const (
	HTTPServerDuration    = "http.server.request.duration"
	HTTPClientDuration    = "http.client.request.duration"
	RPCServerDuration     = "rpc.server.duration"
	RPCClientDuration     = "rpc.client.duration"
	SQLClientDuration     = "sql.client.duration"
	HTTPServerRequestSize = "http.server.request.body.size"
	HTTPClientRequestSize = "http.client.request.body.size"

	UsualPortGRPC = "4317"
	UsualPortHTTP = "4318"

	AggregationExplicit    = "explicit_bucket_histogram"
	AggregationExponential = "base2_exponential_bucket_histogram"
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
	ReportTarget   bool `yaml:"report_target" env:"BEYLA_METRICS_REPORT_TARGET"`
	ReportPeerInfo bool `yaml:"report_peer" env:"BEYLA_METRICS_REPORT_PEER"`

	Buckets              Buckets `yaml:"buckets"`
	HistogramAggregation string  `yaml:"histogram_aggregation" env:"OTEL_EXPORTER_OTLP_METRICS_DEFAULT_HISTOGRAM_AGGREGATION"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"BEYLA_METRICS_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"BEYLA_OTEL_SDK_LOG_LEVEL"`

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

// Enabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
// nolint:gocritic
func (m MetricsConfig) Enabled() bool {
	return m.CommonEndpoint != "" || m.MetricsEndpoint != "" || m.Grafana.MetricsEnabled()
}

// MetricsReporter implements the graph node that receives request.Span
// instances and forwards them as OTEL metrics.
type MetricsReporter struct {
	ctx       context.Context
	cfg       *MetricsConfig
	exporter  metric.Exporter
	reporters ReporterPool[*Metrics]
}

// Metrics is a set of metrics associated to a given OTEL MeterProvider.
// There is a Metrics instance for each service/process instrumented by Beyla.
type Metrics struct {
	ctx                   context.Context
	provider              *metric.MeterProvider
	httpDuration          instrument.Float64Histogram
	httpClientDuration    instrument.Float64Histogram
	grpcDuration          instrument.Float64Histogram
	grpcClientDuration    instrument.Float64Histogram
	sqlClientDuration     instrument.Float64Histogram
	httpRequestSize       instrument.Float64Histogram
	httpClientRequestSize instrument.Float64Histogram
}

func ReportMetrics(
	ctx context.Context, cfg *MetricsConfig, ctxInfo *global.ContextInfo,
) (node.TerminalFunc[[]request.Span], error) {

	SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

	mr, err := newMetricsReporter(ctx, cfg, ctxInfo)
	if err != nil {
		return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
	}
	return mr.reportMetrics, nil
}

func newMetricsReporter(ctx context.Context, cfg *MetricsConfig, ctxInfo *global.ContextInfo) (*MetricsReporter, error) {
	log := mlog()
	mr := MetricsReporter{
		ctx: ctx,
		cfg: cfg,
	}
	mr.reporters = NewReporterPool[*Metrics](cfg.ReportersCacheLen,
		func(id svc.UID, v *Metrics) {
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

func (mr *MetricsReporter) newMetricSet(service svc.ID) (*Metrics, error) {
	mlog := mlog().With("service", service)
	mlog.Debug("creating new Metrics reporter")
	useExponentialHistograms := isExponentialAggregation(mr.cfg, mlog)
	resources := otelResource(service)
	m := Metrics{
		ctx: mr.ctx,
		provider: metric.NewMeterProvider(
			metric.WithResource(resources),
			metric.WithReader(metric.NewPeriodicReader(mr.exporter,
				metric.WithInterval(mr.cfg.Interval))),
			metric.WithView(otelHistogramConfig(HTTPServerDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(HTTPClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(RPCServerDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(RPCClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(SQLClientDuration, mr.cfg.Buckets.DurationHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(HTTPServerRequestSize, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
			metric.WithView(otelHistogramConfig(HTTPClientRequestSize, mr.cfg.Buckets.RequestSizeHistogram, useExponentialHistograms)),
		),
	}
	// time units for HTTP and GRPC durations are in seconds, according to the OTEL specification:
	// https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/metrics/semantic_conventions
	// TODO: set ExplicitBucketBoundaries here and in prometheus from the previous specification
	var err error
	meter := m.provider.Meter(reporterName)
	m.httpDuration, err = meter.Float64Histogram(HTTPServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	m.httpClientDuration, err = meter.Float64Histogram(HTTPClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	m.grpcDuration, err = meter.Float64Histogram(RPCServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	m.grpcClientDuration, err = meter.Float64Histogram(RPCClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	m.sqlClientDuration, err = meter.Float64Histogram(SQLClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating sql client duration histogram metric: %w", err)
	}
	m.httpRequestSize, err = meter.Float64Histogram(HTTPServerRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	m.httpClientRequestSize, err = meter.Float64Histogram(HTTPClientRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
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

func (mr *MetricsReporter) grpcAttributes(span *request.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		semconv.RPCMethod(span.Path),
		semconv.RPCSystemGRPC,
		semconv.RPCGRPCStatusCodeKey.Int(span.Status),
	}
	if mr.cfg.ReportPeerInfo {
		if span.Type == request.EventTypeGRPC {
			attrs = append(attrs, ClientAddr(span.Peer))
		} else {
			attrs = append(attrs, ServerAddr(span.Peer))
		}
	}

	return attrs
}

func (mr *MetricsReporter) httpServerAttributes(span *request.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		HTTPRequestMethod(span.Method),
		HTTPResponseStatusCode(span.Status),
	}
	if mr.cfg.ReportTarget {
		attrs = append(attrs, HTTPUrlPath(span.Path))
	}
	if mr.cfg.ReportPeerInfo {
		attrs = append(attrs, ClientAddr(span.Peer))
	}
	if span.Route != "" {
		attrs = append(attrs, semconv.HTTPRoute(span.Route))
	}

	return attrs
}

func (mr *MetricsReporter) httpClientAttributes(span *request.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		HTTPRequestMethod(span.Method),
		HTTPResponseStatusCode(span.Status),
	}
	if mr.cfg.ReportPeerInfo {
		attrs = append(attrs, ServerAddr(span.Host))
		attrs = append(attrs, ServerPort(span.HostPort))
	}
	if span.Route != "" {
		attrs = append(attrs, semconv.HTTPRoute(span.Route))
	}

	return attrs
}

func (mr *MetricsReporter) metricAttributes(span *request.Span) attribute.Set {
	var attrs []attribute.KeyValue

	switch span.Type {
	case request.EventTypeHTTP:
		attrs = mr.httpServerAttributes(span)
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		attrs = mr.grpcAttributes(span)
	case request.EventTypeHTTPClient:
		attrs = mr.httpClientAttributes(span)
	case request.EventTypeSQLClient:
		attrs = []attribute.KeyValue{
			semconv.DBOperation(span.Method),
		}
	}

	if span.ServiceID.Name != "" { // we don't have service name set, system wide instrumentation
		attrs = append(attrs, semconv.ServiceName(span.ServiceID.Name))
	}

	return attribute.NewSet(attrs...)
}

func (r *Metrics) record(span *request.Span, attrs attribute.Set) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
	attrOpt := instrument.WithAttributeSet(attrs)
	switch span.Type {
	case request.EventTypeHTTP:
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.httpDuration.Record(r.ctx, duration, attrOpt)
		r.httpRequestSize.Record(r.ctx, float64(span.ContentLength), attrOpt)
	case request.EventTypeGRPC:
		r.grpcDuration.Record(r.ctx, duration, attrOpt)
	case request.EventTypeGRPCClient:
		r.grpcClientDuration.Record(r.ctx, duration, attrOpt)
	case request.EventTypeHTTPClient:
		r.httpClientDuration.Record(r.ctx, duration, attrOpt)
		r.httpClientRequestSize.Record(r.ctx, float64(span.ContentLength), attrOpt)
	case request.EventTypeSQLClient:
		r.sqlClientDuration.Record(r.ctx, duration, attrOpt)
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
			reporter.record(s, mr.metricAttributes(s))
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
