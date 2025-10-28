// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"log/slog"
	"runtime"
	"time"

	"github.com/google/uuid"

	"go.opentelemetry.io/otel/attribute"
	instrument "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

// InternalMetricsReporter is an internal metrics Reporter that exports to OTEL
type InternalMetricsReporter struct {
	ctx                              context.Context
	tracerFlushes                    instrument.Float64Histogram
	otelMetricExports                instrument.Float64Counter
	otelMetricExportErrs             instrument.Float64Counter
	otelTraceExports                 instrument.Float64Counter
	otelTraceExportErrs              instrument.Float64Counter
	instrumentedProcesses            instrument.Int64UpDownCounter
	instrumentationErrors            instrument.Int64Counter
	avoidedServices                  instrument.Int64Gauge
	buildInfo                        instrument.Int64Gauge
	bpfProbeLatencies                instrument.Float64Histogram
	bpfMapEntries                    instrument.Int64Gauge
	bpfMapMaxEntries                 instrument.Int64Gauge
	bpfInternalMetricsScrapeInterval time.Duration
	informerLag                      instrument.Float64Histogram
}

func imlog() *slog.Logger {
	return slog.With("component", "otel.InternalMetricsReporter")
}

func NewInternalMetricsReporter(ctx context.Context, ctxInfo *global.ContextInfo, metrics *otelcfg.MetricsConfig, internalMetrics *imetrics.Config) (*InternalMetricsReporter, error) {
	log := imlog()
	log.Debug("instantiating internal metrics exporter provider")
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}

	res := newResourceInternal(ctxInfo.HostID)
	provider := newInternalMeterProvider(res, &exporter, metrics.Interval)
	meter := provider.Meter("obi_internal")
	tracerFlushes, err := meter.Float64Histogram(
		attr.VendorPrefix+".ebpf.tracer.flushes",
		instrument.WithDescription("Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage"),
		instrument.WithUnit("1"),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExports, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.metric.exports",
		instrument.WithDescription("Length of the metric batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExportErrs, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.metric.export.errors",
		instrument.WithDescription("Error count on each failed OTEL metric export"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExports, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.trace.exports",
		instrument.WithDescription("Length of the trace batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExportErrs, err := meter.Float64Counter(
		attr.VendorPrefix+".otel.trace.export.errors",
		instrument.WithDescription("Error count on each failed OTEL trace export"),
	)
	if err != nil {
		return nil, err
	}

	instrumentedProcesses, err := meter.Int64UpDownCounter(
		attr.VendorPrefix+".instrumented.processes",
		instrument.WithDescription("Total number of instrumented processes by process name"),
	)
	if err != nil {
		return nil, err
	}

	instrumentationErrors, err := meter.Int64Counter(
		attr.VendorPrefix+".instrumentation.errors",
		instrument.WithDescription("Total number of instrumentation errors by process name and error type"),
	)
	if err != nil {
		return nil, err
	}

	avoidedServices, err := meter.Int64Gauge(
		attr.VendorPrefix+".avoided.services",
		instrument.WithDescription("Services avoided due to existing OpenTelemetry instrumentation"),
	)
	if err != nil {
		return nil, err
	}

	buildInfo, err := meter.Int64Gauge(
		attr.VendorPrefix+".internal.build.info",
		instrument.WithDescription("A metric with a constant '1' value labeled by version, revision, branch, goversion, goos and goarch during build."),
	)
	if err != nil {
		return nil, err
	}

	// TODO should it be ebpf like the others, or bpf like the original one?
	bpfProbeLatencies, err := meter.Float64Histogram(
		attr.VendorPrefix+".bpf.probe.latency_seconds",
		instrument.WithDescription("Latency of the eBPF probe in seconds"),
		instrument.WithUnit("1"),
		instrument.WithExplicitBucketBoundaries(
			imetrics.BpfLatenciesBuckets...,
		),
	)
	if err != nil {
		return nil, err
	}
	bpfMapEntries, err := meter.Int64Gauge(
		attr.VendorPrefix+".bpf.map.entries_total",
		instrument.WithDescription("Number of entries in the eBPF map"),
	)
	if err != nil {
		return nil, err
	}
	bpfMapMaxEntries, err := meter.Int64Gauge(
		attr.VendorPrefix+".bpf.map.max_entries_total",
		instrument.WithDescription("Max number of entries in the eBPF map"),
	)
	if err != nil {
		return nil, err
	}

	return &InternalMetricsReporter{
		ctx:                              ctx,
		tracerFlushes:                    tracerFlushes,
		otelMetricExports:                otelMetricExports,
		otelMetricExportErrs:             otelMetricExportErrs,
		otelTraceExports:                 otelTraceExports,
		otelTraceExportErrs:              otelTraceExportErrs,
		instrumentedProcesses:            instrumentedProcesses,
		instrumentationErrors:            instrumentationErrors,
		avoidedServices:                  avoidedServices,
		buildInfo:                        buildInfo,
		bpfProbeLatencies:                bpfProbeLatencies,
		bpfMapEntries:                    bpfMapEntries,
		bpfMapMaxEntries:                 bpfMapMaxEntries,
		bpfInternalMetricsScrapeInterval: internalMetrics.BpfMetricScrapeInterval,
	}, nil
}

func newInternalMeterProvider(res *resource.Resource, exporter *metric.Exporter, interval time.Duration) *metric.MeterProvider {
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
}

func (p *InternalMetricsReporter) Start(ctx context.Context) {
	p.buildInfo.Record(ctx, 1, instrument.WithAttributes(attribute.String("goarch", runtime.GOARCH), attribute.String("goos", runtime.GOOS), attribute.String("goversion", runtime.Version()), attribute.String("version", buildinfo.Version), attribute.String("revision", buildinfo.Revision)))
}

func (p *InternalMetricsReporter) TracerFlush(length int) {
	p.tracerFlushes.Record(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExport(length int) {
	p.otelMetricExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExportError(err error) {
	p.otelMetricExportErrs.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("error", err.Error())))
}

func (p *InternalMetricsReporter) OTELTraceExport(length int) {
	p.otelTraceExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELTraceExportError(err error) {
	p.otelTraceExportErrs.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("error", err.Error())))
}

func (p *InternalMetricsReporter) PrometheusRequest(_, _ string) {
}

func (p *InternalMetricsReporter) InstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, 1, instrument.WithAttributes(attribute.String("process_name", processName)))
}

func (p *InternalMetricsReporter) UninstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, -1, instrument.WithAttributes(attribute.String("process_name", processName)))
}

func (p *InternalMetricsReporter) InstrumentationError(processName, errorType string) {
	p.instrumentationErrors.Add(p.ctx, 1, instrument.WithAttributes(
		attribute.String("process_name", processName),
		attribute.String("error_type", errorType),
	))
}

func newResourceInternal(hostID string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("opentelemetry-ebpf-instrumentation"),
		semconv.ServiceInstanceID(uuid.New().String()),
		semconv.TelemetrySDKLanguageKey.String(semconv.TelemetrySDKLanguageGo.Value.AsString()),
		semconv.TelemetrySDKNameKey.String("opentelemetry-ebpf-instrumentation"),
		semconv.HostID(hostID),
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

func (p *InternalMetricsReporter) recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, telemetryType string) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
		semconv.ServiceNamespace(serviceNamespace),
		semconv.ServiceInstanceID(serviceInstanceID),
		attribute.String("telemetry.type", telemetryType),
	}

	p.avoidedServices.Record(p.ctx, 1, instrument.WithAttributes(attrs...))
}

func (p *InternalMetricsReporter) AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "metrics")
}

func (p *InternalMetricsReporter) AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "traces")
}

func (p *InternalMetricsReporter) BpfProbeLatency(probeID, probeType, probeName string, latencySeconds float64) {
	attrs := []attribute.KeyValue{
		attribute.String("bpf.probe.id", probeID),
		attribute.String("bpf.probe.type", probeType),
		attribute.String("bpf.probe.name", probeName),
	}

	p.bpfProbeLatencies.Record(p.ctx, latencySeconds, instrument.WithAttributes(attrs...))
}

func (p *InternalMetricsReporter) BpfMapEntries(mapID, mapName, mapType string, entriesTotal int) {
	attrs := []attribute.KeyValue{
		attribute.String("bpf.map.id", mapID),
		attribute.String("bpf.map.type", mapType),
		attribute.String("bpf.map.name", mapName),
	}
	p.bpfMapEntries.Record(p.ctx, int64(entriesTotal), instrument.WithAttributes(attrs...))
}

func (p *InternalMetricsReporter) BpfMapMaxEntries(mapID, mapName, mapType string, maxEntries int) {
	attrs := []attribute.KeyValue{
		attribute.String("bpf.map.id", mapID),
		attribute.String("bpf.map.type", mapType),
		attribute.String("bpf.map.name", mapName),
	}
	p.bpfMapMaxEntries.Record(p.ctx, int64(maxEntries), instrument.WithAttributes(attrs...))
}

func (p *InternalMetricsReporter) BpfInternalMetricsScrapeInterval() time.Duration {
	return p.bpfInternalMetricsScrapeInterval
}

func (p *InternalMetricsReporter) InformerLag(seconds float64) {
	p.informerLag.Record(p.ctx, seconds)
}
