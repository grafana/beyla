// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

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
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

const internalMetricsMeterName = "obi_internal"

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
	avoidedServicesLimiter           *avoidedsvc.Limiter
	buildInfo                        instrument.Int64Gauge
	bpfProbeLatency                  *bpfProbeLatencyProducer
	bpfMapEntries                    instrument.Int64Gauge
	bpfMapMaxEntries                 instrument.Int64Gauge
	bpfInternalMetricsScrapeInterval time.Duration
	informerLag                      instrument.Float64Histogram
	// used for calculating deltas from an absolute value
	totalPackets          uint64
	totalIgnoredPackets   uint64
	bpfPacketCount        instrument.Int64Counter
	bpfIgnoredPacketCount instrument.Int64Counter

	queueCapacityRatio instrument.Float64Gauge

	internalAttrs attr.InternalAttributes
}

func imlog() *slog.Logger {
	return slog.With("component", "otel.InternalMetricsReporter")
}

func NewInternalMetricsReporter(ctx context.Context, ctxInfo *global.ContextInfo, metrics *otelcfg.MetricsConfig, internalMetrics *imetrics.InternalMetricsConfig) (*InternalMetricsReporter, error) {
	log := imlog()
	log.Debug("instantiating internal metrics exporter provider")
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}

	internalNames := attributes.NewInternalMetrics(attr.VendorPrefix)
	internalAttrs := attr.NewInternalAttributes(attr.VendorPrefix)

	res := newResourceInternal(&ctxInfo.NodeMeta)
	bpfProbeLatency := newBpfProbeLatencyProducer(
		internalNames.BpfProbeLatency,
		exporter.Temporality(metric.InstrumentKindHistogram),
	)
	provider := newInternalMeterProvider(res, &exporter, metrics.Interval, bpfProbeLatency)
	meter := provider.Meter(internalMetricsMeterName)
	tracerFlushes, err := meter.Float64Histogram(
		internalNames.TracerFlushes.OTEL,
		instrument.WithDescription("Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage"),
		instrument.WithUnit(internalNames.TracerFlushes.Unit),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExports, err := meter.Float64Counter(
		internalNames.OTELMetricExports.OTEL,
		instrument.WithDescription("Length of the metric batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelMetricExportErrs, err := meter.Float64Counter(
		internalNames.OTELMetricExportErrors.OTEL,
		instrument.WithDescription("Error count on each failed OTEL metric export"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExports, err := meter.Float64Counter(
		internalNames.OTELTraceExports.OTEL,
		instrument.WithDescription("Length of the trace batches submitted to the remote OTEL collector"),
	)
	if err != nil {
		return nil, err
	}

	otelTraceExportErrs, err := meter.Float64Counter(
		internalNames.OTELTraceExportErrors.OTEL,
		instrument.WithDescription("Error count on each failed OTEL trace export"),
	)
	if err != nil {
		return nil, err
	}

	instrumentedProcesses, err := meter.Int64UpDownCounter(
		internalNames.InstrumentedProcesses.OTEL,
		instrument.WithDescription("Total number of instrumented processes by process name"),
	)
	if err != nil {
		return nil, err
	}

	instrumentationErrors, err := meter.Int64Counter(
		internalNames.InstrumentationErrors.OTEL,
		instrument.WithDescription("Total number of instrumentation errors by process name and error type"),
	)
	if err != nil {
		return nil, err
	}

	var avoidedServices instrument.Int64Gauge
	var avoidedServicesLimiter *avoidedsvc.Limiter
	if !internalMetrics.AvoidedServices.Disabled {
		avoidedServices, err = meter.Int64Gauge(
			internalNames.AvoidedServices.OTEL,
			instrument.WithDescription("Services avoided due to existing OpenTelemetry instrumentation"),
		)
		if err != nil {
			return nil, err
		}
		avoidedServicesLimiter = avoidedsvc.NewLimiter(internalMetrics.AvoidedServices.Limit)
	}

	buildInfo, err := meter.Int64Gauge(
		internalNames.BuildInfo.OTEL,
		instrument.WithDescription("A metric with a constant '1' value labeled by version, revision, branch, goversion, goos and goarch during build."),
	)
	if err != nil {
		return nil, err
	}

	bpfMapEntries, err := meter.Int64Gauge(
		internalNames.BpfMapEntries.OTEL,
		instrument.WithDescription("Number of entries in the eBPF map"),
	)
	if err != nil {
		return nil, err
	}
	bpfMapMaxEntries, err := meter.Int64Gauge(
		internalNames.BpfMapMaxEntries.OTEL,
		instrument.WithDescription("Max number of entries in the eBPF map"),
	)
	if err != nil {
		return nil, err
	}

	informerLag, err := meter.Float64Histogram(
		internalNames.KubeCacheForwardLag.OTEL,
		instrument.WithDescription("How long, in seconds, it takes since a Kubernetes event happens until it is forwarded to the subscribers"),
		instrument.WithUnit(internalNames.KubeCacheForwardLag.Unit),
		instrument.WithExplicitBucketBoundaries(
			imetrics.InformerLagBuckets...,
		),
	)
	if err != nil {
		return nil, err
	}

	bpfIgnoredPacketCount, err := meter.Int64Counter(
		internalNames.BpfNetworkIgnoredPackets.OTEL,
		instrument.WithDescription("How many network packets have been internally ignored due to collisions in the internal eBPF cache"),
		instrument.WithUnit(internalNames.BpfNetworkIgnoredPackets.Unit),
	)
	if err != nil {
		return nil, err
	}

	bpfPacketCount, err := meter.Int64Counter(
		internalNames.BpfNetworkPackets.OTEL,
		instrument.WithDescription("How many network packets have been internally accounted"),
		instrument.WithUnit(internalNames.BpfNetworkPackets.Unit),
	)
	if err != nil {
		return nil, err
	}

	queueCapacityRatio, err := meter.Float64Gauge(
		internalNames.QueueCapacityRatio.OTEL,
		instrument.WithDescription("Ratio [0-1] between the unread messages of an internal Go channel and its total capacity"),
		instrument.WithUnit(internalNames.QueueCapacityRatio.Unit))
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
		avoidedServicesLimiter:           avoidedServicesLimiter,
		buildInfo:                        buildInfo,
		bpfProbeLatency:                  bpfProbeLatency,
		bpfMapEntries:                    bpfMapEntries,
		bpfMapMaxEntries:                 bpfMapMaxEntries,
		bpfInternalMetricsScrapeInterval: internalMetrics.BpfMetricScrapeInterval,
		informerLag:                      informerLag,
		bpfPacketCount:                   bpfPacketCount,
		bpfIgnoredPacketCount:            bpfIgnoredPacketCount,
		queueCapacityRatio:               queueCapacityRatio,
		internalAttrs:                    internalAttrs,
	}, nil
}

func newInternalMeterProvider(
	res *resource.Resource,
	exporter *metric.Exporter,
	interval time.Duration,
	bpfProbeLatency *bpfProbeLatencyProducer,
) *metric.MeterProvider {
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter,
			metric.WithInterval(interval),
			metric.WithProducer(bpfProbeLatency))),
	)
}

// sanitizedAttributes is the attribute boundary for the internal metrics, which build their
// datapoint attributes directly rather than through Expirer.recordAttributes. A value such as
// a process basename can carry invalid UTF-8, which protobuf rejects for the whole export
// request, so every one of them passes through here.
func sanitizedAttributes(kvs ...attribute.KeyValue) instrument.MeasurementOption {
	sanitized := make([]attribute.KeyValue, len(kvs))
	for i, kv := range kvs {
		sanitized[i] = sanitizeKeyValue(kv)
	}

	return instrument.WithAttributes(sanitized...)
}

func (p *InternalMetricsReporter) Start(ctx context.Context) {
	p.buildInfo.Record(ctx, 1, sanitizedAttributes(
		attribute.String(string(p.internalAttrs.Goarch), runtime.GOARCH),
		attribute.String(string(p.internalAttrs.Goos), runtime.GOOS),
		attribute.String(string(p.internalAttrs.Goversion), runtime.Version()),
		attribute.String(string(p.internalAttrs.Version), buildinfo.Version),
		attribute.String(string(p.internalAttrs.Revision), buildinfo.Revision),
	))
}

func (p *InternalMetricsReporter) TracerFlush(length int) {
	p.tracerFlushes.Record(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExport(length int) {
	p.otelMetricExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELMetricExportError(err error) {
	p.otelMetricExportErrs.Add(p.ctx, 1, sanitizedAttributes(attribute.String(string(attr.ErrorType), imetrics.ExportErrorType(err))))
}

func (p *InternalMetricsReporter) OTELTraceExport(length int) {
	p.otelTraceExports.Add(p.ctx, float64(length))
}

func (p *InternalMetricsReporter) OTELTraceExportError(err error) {
	p.otelTraceExportErrs.Add(p.ctx, 1, sanitizedAttributes(attribute.String(string(attr.ErrorType), imetrics.ExportErrorType(err))))
}

func (p *InternalMetricsReporter) PrometheusRequest(_, _ string) {
}

func (p *InternalMetricsReporter) InstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, 1, sanitizedAttributes(attribute.String(string(attr.ProcessExecutableName), processName)))
}

func (p *InternalMetricsReporter) UninstrumentProcess(processName string) {
	p.instrumentedProcesses.Add(p.ctx, -1, sanitizedAttributes(attribute.String(string(attr.ProcessExecutableName), processName)))
}

func (p *InternalMetricsReporter) InstrumentationError(processName, errorType string) {
	p.instrumentationErrors.Add(p.ctx, 1, sanitizedAttributes(
		attribute.String(string(attr.ProcessExecutableName), processName),
		attribute.String(string(attr.ErrorType), errorType),
	))
}

func newResourceInternal(nodeMeta *meta.NodeMeta) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(attr.TelemetryDistroName),
		semconv.ServiceInstanceID(uuid.New().String()),
		semconv.TelemetrySDKLanguageKey.String(semconv.TelemetrySDKLanguageGo.Value.AsString()),
		semconv.TelemetrySDKNameKey.String(attr.VendorSDKName),
		semconv.TelemetrySDKVersion(attr.VendorSDKVersion),
		semconv.TelemetryDistroName(attr.TelemetryDistroName),
		semconv.TelemetryDistroVersion(attr.TelemetryDistroVersion),
		semconv.HostID(nodeMeta.HostID),
	}

	for _, event := range nodeMeta.Metadata {
		attrs = append(attrs, event.Key.OTEL().String(event.Value))
	}

	return resource.NewWithAttributes(attr.OBISchemaURL, attrs...)
}

func (p *InternalMetricsReporter) recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, telemetryType string) {
	if p.avoidedServices == nil {
		return
	}

	labels := p.avoidedServicesLimiter.Labels(serviceName, serviceNamespace, serviceInstanceID, telemetryType)
	var attrs []attribute.KeyValue
	if labels.Overflow {
		attrs = []attribute.KeyValue{
			attribute.Bool(avoidedsvc.OverflowAttribute, true),
		}
	} else {
		attrs = []attribute.KeyValue{
			semconv.ServiceName(labels.ServiceName),
			semconv.ServiceNamespace(labels.ServiceNamespace),
			attribute.String(string(attr.TelemetryType), labels.TelemetryType),
		}
	}

	p.avoidedServices.Record(p.ctx, 1, sanitizedAttributes(attrs...))
}

func (p *InternalMetricsReporter) AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "metrics")
}

func (p *InternalMetricsReporter) AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "traces")
}

func (p *InternalMetricsReporter) BpfProbeStats(probeID, probeType, probeName string, count uint64, latencySumSeconds float64, latencyBuckets map[float64]uint64) {
	p.bpfProbeLatency.Update(probeID, probeType, probeName, count, latencySumSeconds, latencyBuckets)
}

func (p *InternalMetricsReporter) BpfMapEntries(mapID, mapName, mapType string, entriesTotal int) {
	attrs := []attribute.KeyValue{
		attribute.String(string(attr.BpfMapID), mapID),
		attribute.String(string(attr.BpfMapType), mapType),
		attribute.String(string(attr.BpfMapName), mapName),
	}
	p.bpfMapEntries.Record(p.ctx, int64(entriesTotal), sanitizedAttributes(attrs...))
}

func (p *InternalMetricsReporter) BpfMapMaxEntries(mapID, mapName, mapType string, maxEntries int) {
	attrs := []attribute.KeyValue{
		attribute.String(string(attr.BpfMapID), mapID),
		attribute.String(string(attr.BpfMapType), mapType),
		attribute.String(string(attr.BpfMapName), mapName),
	}
	p.bpfMapMaxEntries.Record(p.ctx, int64(maxEntries), sanitizedAttributes(attrs...))
}

func (p *InternalMetricsReporter) BpfInternalMetricsScrapeInterval() time.Duration {
	return p.bpfInternalMetricsScrapeInterval
}

func (p *InternalMetricsReporter) InformerLag(seconds float64) {
	p.informerLag.Record(p.ctx, seconds)
}

func (p *InternalMetricsReporter) BPFPacketStats(count, ignored uint64) {
	p.bpfPacketCount.Add(p.ctx, int64(count-p.totalPackets))
	p.bpfIgnoredPacketCount.Add(p.ctx, int64(ignored-p.totalIgnoredPackets))
	p.totalPackets, p.totalIgnoredPackets = count, ignored
}

func (p *InternalMetricsReporter) QueueBufferUtilization(subscriber string, ratio float64) {
	p.queueCapacityRatio.Record(p.ctx, ratio, sanitizedAttributes(attribute.String(string(attr.Subscriber), subscriber)))
}
