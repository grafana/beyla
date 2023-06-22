package otel

import (
	"context"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/trace"
)

// instrumentedMetricsExporter wraps an otel metrics exporter to account some internal metrics
type instrumentedMetricsExporter struct {
	metric.Exporter
	internal imetrics.Reporter
}

func (ie *instrumentedMetricsExporter) Export(ctx context.Context, md metricdata.ResourceMetrics) error {
	if err := ie.Exporter.Export(ctx, md); err != nil {
		ie.internal.OTELMetricExportError(err)
		return err
	}
	totalMetrics := 0
	for _, scope := range md.ScopeMetrics {
		totalMetrics += len(scope.Metrics)
	}
	ie.internal.OTELMetricExport(totalMetrics)
	return nil
}

type instrumentedTracesExporter struct {
	trace.SpanExporter
	internal imetrics.Reporter
}

func (ie *instrumentedTracesExporter) ExportSpans(ctx context.Context, ss []trace.ReadOnlySpan) error {
	if err := ie.SpanExporter.ExportSpans(ctx, ss); err != nil {
		ie.internal.OTELTraceExportError(err)
		return err
	}
	ie.internal.OTELTraceExport(len(ss))
	return nil
}
