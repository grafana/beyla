package otel

import (
	"context"
	"fmt"
	"os"
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
	ServiceName     string        `yaml:"service_name" env:"SERVICE_NAME"`
	Interval        time.Duration `yaml:"interval" env:"METRICS_INTERVAL"`
	Endpoint        string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	MetricsEndpoint string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"`
	// ReportTarget specifies whether http.target should be submitted as a metric attribute. It is disabled by
	// default to avoid cardinality explosion in paths with IDs. In that case, it is recommended to group these
	// requests in the Routes node
	ReportTarget   bool `yaml:"report_target" env:"OTEL_EXPORTER_REPORT_TARGET"`
	ReportPeerInfo bool `yaml:"report_peer" env:"OTEL_EXPORTER_REPORT_PEER"`
}

// Enabled specifies that the OTEL metrics node is enabled if and only if
// either the OTEL endpoint and OTEL metrics endpoint is defined.
// If not enabled, this node won't be instantiated
func (m MetricsConfig) Enabled() bool {
	return m.Endpoint != "" || m.MetricsEndpoint != ""
}

type MetricsReporter struct {
	reportTarget bool
	reportPeer   bool
	exporter     metric.Exporter
	provider     *metric.MeterProvider
	duration     instrument.Float64Histogram
}

func MetricsReporterProvider(cfg MetricsConfig) node.TerminalFunc[transform.HTTPRequestSpan] {
	mr, err := newMetricsReporter(&cfg)
	if err != nil {
		slog.Error("can't instantiate OTEL metrics reporter", err)
		os.Exit(-1)
	}
	return mr.reportMetrics
}

func newMetricsReporter(cfg *MetricsConfig) (*MetricsReporter, error) {
	ctx := context.TODO()

	endpoint := cfg.MetricsEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}

	mr := MetricsReporter{
		reportTarget: cfg.ReportTarget,
		reportPeer:   cfg.ReportPeerInfo,
	}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(cfg.ServiceName),
	)
	var err error
	// TODO: allow configuring auth headers and secure/insecure connections
	mr.exporter, err = otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithEndpoint(endpoint),
		otlpmetrichttp.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("creating metric exporter: %w", err)
	}
	mr.provider = metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(cfg.Interval))),
	)
	mr.duration, err = mr.provider.Meter(reporterName).
		Float64Histogram("duration", instrument.WithUnit("ms"))
	if err != nil {
		return nil, fmt.Errorf("creating duration histogram metric: %w", err)
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

func (r *MetricsReporter) reportMetrics(spans <-chan transform.HTTPRequestSpan) {
	defer r.close()
	for span := range spans {
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
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.duration.Record(context.TODO(), span.End.Sub(span.Start).Seconds()*1000, attrs...)
	}
}
