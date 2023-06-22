package otel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"

	"go.opentelemetry.io/otel/sdk/instrumentation"

	"go.opentelemetry.io/otel/sdk/metric/aggregation"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/sdk/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

const (
	HTTPServerDuration    = "http.server.duration"
	HTTPClientDuration    = "http.client.duration"
	RPCServerDuration     = "rpc.server.duration"
	RPCClientDuration     = "rpc.client.duration"
	HTTPServerRequestSize = "http.server.request.size"
	HTTPClientRequestSize = "http.client.request.size"
)

// DurationHistogramBoundaries is specified in the OTEL specification
// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md
// TODO: allow user overriding them
var DurationHistogramBoundaries = []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10}

type MetricsConfig struct {
	ServiceName      string `yaml:"service_name" env:"OTEL_SERVICE_NAME"`
	ServiceNamespace string `yaml:"service_namespace" env:"SERVICE_NAMESPACE"`

	Interval        time.Duration `yaml:"interval" env:"METRICS_INTERVAL"`
	Endpoint        string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_INSECURE_SKIP_VERIFY"`

	// ReportTarget specifies whether http.target should be submitted as a metric attribute. It is disabled by
	// default to avoid cardinality explosion in paths with IDs. In that case, it is recommended to group these
	// requests in the Routes node
	ReportTarget   bool `yaml:"report_target" env:"METRICS_REPORT_TARGET"`
	ReportPeerInfo bool `yaml:"report_peer" env:"METRICS_REPORT_PEER"`
}

// Enabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
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

func MetricsReporterProvider(ctx context.Context, cfg MetricsConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) {
	mr, err := newMetricsReporter(ctx, &cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating OTEL metrics reporter: %w", err)
	}
	return mr.reportMetrics, nil
}

func newMetricsReporter(ctx context.Context, cfg *MetricsConfig) (*MetricsReporter, error) {
	mr := MetricsReporter{
		ctx:          ctx,
		reportTarget: cfg.ReportTarget,
		reportPeer:   cfg.ReportPeerInfo,
	}

	resources := otelResource(ctx, cfg.ServiceName, cfg.ServiceNamespace)

	opts, err := getMetricEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	mexp, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mr.exporter = instrumentMetricsExporter(ctx, mexp)

	// changes
	mr.provider = metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(cfg.Interval))),
		metric.WithView(otelHistogramBuckets(HTTPServerDuration)),
		metric.WithView(otelHistogramBuckets(HTTPClientDuration)),
		metric.WithView(otelHistogramBuckets(RPCServerDuration)),
		metric.WithView(otelHistogramBuckets(RPCClientDuration)),
		// TODO: add specific buckets also for request sizes
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

func otelHistogramBuckets(metricName string) metric.View {
	return metric.NewView(
		metric.Instrument{
			Name:  metricName,
			Scope: instrumentation.Scope{Name: reporterName},
		},
		metric.Stream{
			Name: metricName,
			Aggregation: aggregation.ExplicitBucketHistogram{
				Boundaries: DurationHistogramBoundaries,
			},
		})
}

func (r *MetricsReporter) metricAttributes(span *transform.HTTPRequestSpan) []attribute.KeyValue {
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

	return attrs
}

func (r *MetricsReporter) record(span *transform.HTTPRequestSpan, attrs []attribute.KeyValue) {
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
	switch span.Type {
	case transform.EventTypeHTTP:
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.httpDuration.Record(r.ctx, duration, attrs...)
		r.httpRequestSize.Record(r.ctx, float64(span.ContentLength), attrs...)
	case transform.EventTypeGRPC:
		r.grpcDuration.Record(r.ctx, duration, attrs...)
	case transform.EventTypeGRPCClient:
		r.grpcClientDuration.Record(r.ctx, duration, attrs...)
	case transform.EventTypeHTTPClient:
		r.httpClientDuration.Record(r.ctx, duration, attrs...)
		r.httpClientRequestSize.Record(r.ctx, float64(span.ContentLength), attrs...)
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

// Linter disabled by reason: cyclomatic complexity reaches 11 but the function is almost flat.
//
//nolint:cyclop
func getMetricEndpointOptions(cfg *MetricsConfig) ([]otlpmetrichttp.Option, error) {
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

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	if len(murl.Path) > 0 && murl.Path != "/" && !strings.HasSuffix(murl.Path, "/v1/metrics") {
		opts = append(opts, otlpmetrichttp.WithURLPath(murl.Path+"/v1/metrics"))
	}
	if cfg.InsecureSkipVerify {
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	return opts, nil
}
