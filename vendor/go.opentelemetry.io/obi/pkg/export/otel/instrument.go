// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"

	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/ptrace"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/imetrics"
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

// instrumentedTracesExporter wraps an otel traces exporter to account some internal metrics
type instrumentedTracesExporter struct {
	exporter.Traces
	internal imetrics.Reporter
}

func (ie *instrumentedTracesExporter) ConsumeTraces(ctx context.Context, td ptrace.Traces) error {
	if err := ie.Traces.ConsumeTraces(ctx, td); err != nil {
		ie.internal.OTELTraceExportError(err)
		return err
	}
	ie.internal.OTELTraceExport(td.SpanCount())
	return nil
}
