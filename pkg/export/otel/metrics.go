package otel

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

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
	reportTarget    bool
	reportPeer      bool
	exporter        metric.Exporter
	provider        *metric.MeterProvider
	httpDuration    instrument.Float64Histogram
	grpcDuration    instrument.Float64Histogram
	httpRequestSize instrument.Float64Histogram
}

func MetricsReporterProvider(cfg MetricsConfig) node.TerminalFunc[[]transform.HTTPRequestSpan] {
	mr, err := newMetricsReporter(&cfg)
	if err != nil {
		slog.Error("can't instantiate OTEL metrics reporter", err)
		os.Exit(-1)
	}
	return mr.reportMetrics
}

func newMetricsReporter(cfg *MetricsConfig) (*MetricsReporter, error) {
	ctx := context.TODO()

	mr := MetricsReporter{
		reportTarget: cfg.ReportTarget,
		reportPeer:   cfg.ReportPeerInfo,
	}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(cfg.ServiceName),
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
	mr.httpDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram("http.server.duration", instrument.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("creating http duration histogram metric: %w", err)
	}
	mr.grpcDuration, err = mr.provider.Meter(reporterName).
		Float64Histogram("rpc.server.duration", instrument.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("creating grpc duration histogram metric: %w", err)
	}
	mr.httpRequestSize, err = mr.provider.Meter(reporterName).
		Float64Histogram("http.server.request.size", instrument.WithUnit("By"))
	if err != nil {
		return nil, fmt.Errorf("creating http size histogram metric: %w", err)
	}
	return &mr, nil
}

func (r *MetricsReporter) close() {
	if err := r.provider.Shutdown(context.TODO()); err != nil {
		slog.With("component", "MetricsReporter").Error("closing metrics provider", err)
	}
	if err := r.exporter.Shutdown(context.TODO()); err != nil {
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
	case transform.EventTypeGRPC:
		attrs := []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
		}
		if r.reportPeer {
			attrs = append(attrs, semconv.NetSockPeerAddr(span.Peer))
		}
		return attrs
	}

	return []attribute.KeyValue{}
}

func (r *MetricsReporter) record(span *transform.HTTPRequestSpan, attrs []attribute.KeyValue) {
	switch span.Type {
	case transform.EventTypeHTTP:
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.httpDuration.Record(context.TODO(), span.End.Sub(span.RequestStart).Seconds()*1000, attrs...)
		r.httpRequestSize.Record(context.TODO(), float64(span.ContentLength), attrs...)
	case transform.EventTypeGRPC:
		r.grpcDuration.Record(context.TODO(), span.End.Sub(span.RequestStart).Seconds()*1000, attrs...)
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
