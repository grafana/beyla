package otel

import (
	"context"
	"fmt"

	"golang.org/x/exp/slog"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/http-autoinstrument/pkg/spanner"
)

type MetricsReporter struct {
	exporter metric.Exporter
	provider *metric.MeterProvider
	duration instrument.Float64Histogram
}

func NewMetricsReporter(svcName, endpoint string) (*MetricsReporter, error) {
	ctx := context.TODO()

	mr := MetricsReporter{}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(svcName),
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
		metric.WithReader(metric.NewPeriodicReader(mr.exporter)), // TODO: configure
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

func (r *MetricsReporter) ReportMetrics(spans <-chan spanner.HTTPRequestSpan) {
	defer r.close()
	for span := range spans {
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.duration.Record(context.TODO(),
			span.End.Sub(span.Start).Seconds()*1000,
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPTarget(span.Path),
		)
	}
}
