package otel

import (
	"context"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
)

// instrumentedMetricsExporter wraps an otel metrics exporter to account some internal metrics
type instrumentedMetricsExporter struct {
	sdkmetric.Exporter
	internal imetrics.Reporter
}

func (ie *instrumentedMetricsExporter) Export(ctx context.Context, md *metricdata.ResourceMetrics) error {
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
