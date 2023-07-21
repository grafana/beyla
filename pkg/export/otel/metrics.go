package otel

import (
	"context"
	"crypto/tls"
	"fmt"
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
	"go.opentelemetry.io/otel/sdk/metric/aggregation"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/credentials"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

func mlog() *slog.Logger {
	return slog.With("component", "otel.MetricsReporter")
}

const (
	HTTPServerDuration    = "http.server.duration"
	HTTPClientDuration    = "http.client.duration"
	RPCServerDuration     = "rpc.server.duration"
	RPCClientDuration     = "rpc.client.duration"
	HTTPServerRequestSize = "http.server.request.size"
	HTTPClientRequestSize = "http.client.request.size"
)

type MetricsConfig struct {
	ServiceName      string `yaml:"service_name" env:"OTEL_SERVICE_NAME"`
	ServiceNamespace string `yaml:"service_namespace" env:"SERVICE_NAMESPACE"`

	Interval        time.Duration `yaml:"interval" env:"METRICS_INTERVAL"`
	Endpoint        string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	Protocol        Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	MetricsProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_INSECURE_SKIP_VERIFY"`

	// ReportTarget specifies whether http.target should be submitted as a metric attribute. It is disabled by
	// default to avoid cardinality explosion in paths with IDs. In that case, it is recommended to group these
	// requests in the Routes node
	ReportTarget   bool `yaml:"report_target" env:"METRICS_REPORT_TARGET"`
	ReportPeerInfo bool `yaml:"report_peer" env:"METRICS_REPORT_PEER"`

	Buckets Buckets `yaml:"buckets"`
}

func (m *MetricsConfig) GetProtocol() Protocol {
	if m.MetricsProtocol != "" {
		return m.MetricsProtocol
	}
	return m.Protocol
}

// Enabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
// nolint:gocritic
func (m MetricsConfig) Enabled() bool {
	return m.Endpoint != "" || m.MetricsEndpoint != ""
}

type MetricsReporter struct {
	ctx                   context.Context
	reportTarget          bool
	reportPeer            bool
	exporter              metric.Exporter
	provider              *metric.MeterProvider
	httpDuration          instrument.Float64Histogram
	httpClientDuration    instrument.Float64Histogram
	grpcDuration          instrument.Float64Histogram
	grpcClientDuration    instrument.Float64Histogram
	httpRequestSize       instrument.Float64Histogram
	httpClientRequestSize instrument.Float64Histogram
}

// Reason to disable linting: it requires to be a value despite it is considered a "heavy struct".
// This method is invoked only once during startup time so it doesn't have a noticeable performance impact.
// nolint:gocritic
func MetricsReporterProvider(ctx context.Context, cfg MetricsConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	mr, err := newMetricsReporter(ctx, &cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
	}
	return mr.reportMetrics, nil
}

func newMetricsReporter(ctx context.Context, cfg *MetricsConfig) (*MetricsReporter, error) {
	log := mlog()
	mr := MetricsReporter{
		ctx:          ctx,
		reportTarget: cfg.ReportTarget,
		reportPeer:   cfg.ReportPeerInfo,
	}

	// Instantiate the OTLP HTTP or GRPC metrics exporter
	exporter, err := instantiateMetricsExporter(ctx, cfg, log)
	if err != nil {
		return nil, err
	}
	mr.exporter = instrumentMetricsExporter(ctx, exporter)

	resources := otelResource(ctx, cfg.ServiceName, cfg.ServiceNamespace)
	// changes
	mr.provider = metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(cfg.Interval))),
		metric.WithView(otelHistogramBuckets(HTTPServerDuration, cfg.Buckets.DurationHistogram)),
		metric.WithView(otelHistogramBuckets(HTTPClientDuration, cfg.Buckets.DurationHistogram)),
		metric.WithView(otelHistogramBuckets(RPCServerDuration, cfg.Buckets.DurationHistogram)),
		metric.WithView(otelHistogramBuckets(RPCClientDuration, cfg.Buckets.DurationHistogram)),
		metric.WithView(otelHistogramBuckets(HTTPServerRequestSize, cfg.Buckets.RequestSizeHistogram)),
		metric.WithView(otelHistogramBuckets(HTTPClientRequestSize, cfg.Buckets.RequestSizeHistogram)),
	)
	// time units for HTTP and GRPC durations are in seconds, according to the OTEL specification:
	// https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/metrics/semantic_conventions
	// TODO: set ExplicitBucketBoundaries here and in prometheus from the previous specification
	meter := mr.provider.Meter(reporterName)
	mr.httpDuration, err = meter.Float64Histogram(HTTPServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	mr.httpClientDuration, err = meter.Float64Histogram(HTTPClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	mr.grpcDuration, err = meter.Float64Histogram(RPCServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	mr.grpcClientDuration, err = meter.Float64Histogram(RPCClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	mr.httpRequestSize, err = meter.Float64Histogram(HTTPServerRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	mr.httpClientRequestSize, err = meter.Float64Histogram(HTTPClientRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	return &mr, nil
}

func instantiateMetricsExporter(ctx context.Context, cfg *MetricsConfig, log *slog.Logger) (metric.Exporter, error) {
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
	mexp, err := otlpmetrichttp.New(ctx, opts...)
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
	mexp, err := otlpmetricgrpc.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC metric exporter: %w", err)
	}
	return mexp, nil
}

func (r *MetricsReporter) close() {
	if err := r.provider.Shutdown(r.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", err)
	}
}

// instrumentMetricsExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed metrics exporter inside an instrumented exporter
func instrumentMetricsExporter(ctx context.Context, in metric.Exporter) metric.Exporter {
	internalMetrics := global.Context(ctx).Metrics
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

func otelHistogramBuckets(metricName string, buckets []float64) metric.View {
	return metric.NewView(
		metric.Instrument{
			Name:  metricName,
			Scope: instrumentation.Scope{Name: reporterName},
		},
		metric.Stream{
			Name: metricName,
			Aggregation: aggregation.ExplicitBucketHistogram{
				Boundaries: buckets,
			},
		})
}

func (r *MetricsReporter) metricAttributes(span *transform.HTTPRequestSpan) attribute.Set {
	var attrs []attribute.KeyValue

	switch span.Type {
	case transform.EventTypeHTTP:
		attrs = []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
		}
		if r.reportTarget {
			attrs = append(attrs, semconv.HTTPTarget(span.Path))
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerAddr(span.Peer))
		}
		if span.Route != "" {
			attrs = append(attrs, semconv.HTTPRoute(span.Route))
		}
	case transform.EventTypeGRPC, transform.EventTypeGRPCClient:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerAddr(span.Peer))
		}
	case transform.EventTypeHTTPClient:
		attrs = []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerName(span.Host))
			attrs = append(attrs, semconv.NetSockPeerPort(span.HostPort))
		}
	}

	if span.ServiceName != "" { // we don't have service name set, system wide instrumentation
		attrs = append(attrs, semconv.ServiceName(span.ServiceName))
	}

	return attribute.NewSet(attrs...)
}

func (r *MetricsReporter) record(span *transform.HTTPRequestSpan, attrs attribute.Set) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
	attrOpt := instrument.WithAttributeSet(attrs)
	switch span.Type {
	case transform.EventTypeHTTP:
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.httpDuration.Record(r.ctx, duration, attrOpt)
		r.httpRequestSize.Record(r.ctx, float64(span.ContentLength), attrOpt)
	case transform.EventTypeGRPC:
		r.grpcDuration.Record(r.ctx, duration, attrOpt)
	case transform.EventTypeGRPCClient:
		r.grpcClientDuration.Record(r.ctx, duration, attrOpt)
	case transform.EventTypeHTTPClient:
		r.httpClientDuration.Record(r.ctx, duration, attrOpt)
		r.httpClientRequestSize.Record(r.ctx, float64(span.ContentLength), attrOpt)
	}
}

func (r *MetricsReporter) reportMetrics(input <-chan []transform.HTTPRequestSpan) {
	defer r.close()
	for spans := range input {
		for i := range spans {
			attrs := r.metricAttributes(&spans[i])
			r.record(&spans[i], attrs)
		}
	}
}

func getHTTPMetricEndpointOptions(cfg *MetricsConfig) ([]otlpmetrichttp.Option, error) {
	log := mlog().With("transport", "http")
	murl, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return nil, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(murl.Path) > 0 && murl.Path != "/" && !strings.HasSuffix(murl.Path, "/v1/metrics") {
		urlPath := murl.Path + "/v1/metrics"
		log.Debug("Specifying path", "path", urlPath)
		opts = append(opts, otlpmetrichttp.WithURLPath(urlPath))
	}
	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return opts, nil
}

func getGRPCMetricEndpointOptions(cfg *MetricsConfig) ([]otlpmetricgrpc.Option, error) {
	log := mlog().With("transport", "grpc")
	murl, err := parseMetricsEndpoint(cfg)
	if err != nil {
		return nil, err
	}
	log.Debug("Configuring exporter",
		"protocol", cfg.Protocol, "metricsProtocol", cfg.MetricsProtocol, "endpoint", murl.Host)

	setMetricsProtocol(cfg)
	opts := []otlpmetricgrpc.Option{
		otlpmetricgrpc.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	}
	return opts, nil
}

func parseMetricsEndpoint(cfg *MetricsConfig) (*url.URL, error) {
	endpoint := cfg.MetricsEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, nil
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
	}
}
