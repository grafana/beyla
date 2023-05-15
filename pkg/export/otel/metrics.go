package otel

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
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

type MetricsConfig struct {
	ServiceName     string        `yaml:"service_name" env:"OTEL_SERVICE_NAME"`
	Interval        time.Duration `yaml:"interval" env:"METRICS_INTERVAL"`
	Endpoint        string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
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

	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	svcName := cfg.ServiceName
	if svcName == "" {
		svcName = global.Context(ctx).ServiceName
	}
	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(svcName),
	)
	opts, err := getMetricEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	mr.exporter, err = otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mr.provider = metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(cfg.Interval))),
	)
	// time units for HTTP and GRPC durations are in seconds, according to the OTEL specification:
	// https://github.com/open-telemetry/opentelemetry-specification/tree/main/specification/metrics/semantic_conventions
	// TODO: set ExplicitBucketBoundaries here and in prometheus from the previous specification
	mr.httpDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram(HTTPServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	mr.httpClientDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram(HTTPClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	mr.grpcDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram(RPCServerDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	mr.grpcClientDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram(RPCClientDuration, instrument.WithUnit("s"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	mr.httpRequestSize, err = mr.provider.Meter(reporterName).
		Float64Histogram(HTTPServerRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	mr.httpClientRequestSize, err = mr.provider.Meter(reporterName).
		Float64Histogram(HTTPClientRequestSize, instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	return &mr, nil
}

func (r *MetricsReporter) close() {
	if err := r.provider.Shutdown(r.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", err)
	}
	if err := r.exporter.Shutdown(r.ctx); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics exporter", err)
	}
}

func (r *MetricsReporter) metricAttributes(span *transform.HTTPRequestSpan) []attribute.KeyValue {
	switch span.Type {
	case transform.EventTypeHTTP:
		attrs := []attribute.KeyValue{
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
		return attrs
	case transform.EventTypeGRPC, transform.EventTypeGRPCClient:
		attrs := []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerAddr(span.Peer))
		}
		return attrs
	case transform.EventTypeHTTPClient:
		attrs := []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerName(span.Host))
			attrs = append(attrs, semconv.NetSockPeerPort(span.HostPort))
		}
		return attrs
	}

	return []attribute.KeyValue{}
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
	return opts, nil
}
