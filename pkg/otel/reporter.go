package otel

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/metric/instrument"
	"go.opentelemetry.io/otel/metric/unit"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

const reporterName = "github.com/grafana/http-autoinstrument"

type Reporter struct {
	svcName string

	traceEndpoint string
	traceExporter *otlptrace.Exporter
	traceProvider *trace.TracerProvider

	metricEndpoint string
	metricExporter metric.Exporter
	metricProvider *metric.MeterProvider
	duration       instrument.Float64Histogram
}

func NewReporter(svcName, traceEndpoint, metricEndpoint string) *Reporter {
	return &Reporter{
		svcName:        svcName,
		traceEndpoint:  traceEndpoint,
		metricEndpoint: metricEndpoint,
	}
}

func (r *Reporter) Start() error {
	ctx := context.TODO()

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(r.svcName),
	)

	// Instantiate the OTLP HTTP traceExporter
	if r.traceEndpoint != "" {
		// TODO: better use GRPC (secure)
		var err error
		// TODO: allow configuring auth headers and secure/insecure connections
		r.traceExporter, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(r.traceEndpoint),
			otlptracehttp.WithInsecure(), // TODO: configurable
		)
		if err != nil {
			return fmt.Errorf("creating trace exporter: %w", err)
		}

		r.traceProvider = trace.NewTracerProvider(
			trace.WithResource(resources),
			trace.WithSyncer(r.traceExporter),
		)
	}

	// Instantiate the OTLP HTTP metric exporter
	if r.metricEndpoint != "" {
		var err error
		// TODO: allow configuring auth headers and secure/insecure connections
		r.metricExporter, err = otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpoint(r.metricEndpoint),
			otlpmetrichttp.WithInsecure(),
		)
		if err != nil {
			return fmt.Errorf("creating metric exporter: %w", err)
		}
		r.metricProvider = metric.NewMeterProvider(
			metric.WithResource(resources),
			metric.WithReader(metric.NewPeriodicReader(r.metricExporter)), // TODO: configure
		)
		r.duration, err = r.metricProvider.Meter(reporterName).
			Float64Histogram("duration", instrument.WithUnit(unit.Milliseconds))
		if err != nil {
			return fmt.Errorf("creating duration histogram metric: %w", err)
		}
	}

	return nil
}

func (r *Reporter) Close() error {
	if err := r.traceProvider.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing traces provider: %w", err)
	}
	if err := r.metricProvider.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing metric provider: %w", err)
	}
	if err := r.traceExporter.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing traces expoerter: %w", err)
	}
	if err := r.metricProvider.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("closing metric exporter: %w", err)
	}
	return nil
}
