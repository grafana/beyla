// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/runtimemetrics"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rmlog() *slog.Logger {
	return slog.With("component", "otel.RuntimeMetricsReporter")
}

type RuntimeMetricsReporter struct {
	ctx       context.Context
	cfg       *otelcfg.MetricsConfig
	nodeMeta  meta.NodeMeta
	exporter  sdkmetric.Exporter
	reporters otelcfg.ReporterPool[*svc.Attrs, *RuntimeMetrics]
	input     <-chan []runtimemetrics.RuntimeMetricSnapshot
	log       *slog.Logger
}

type RuntimeMetrics struct {
	ctx      context.Context
	service  *svc.Attrs
	provider *metric.MeterProvider

	goMetrics goRuntimeMetrics
}

type goRuntimeMetrics struct {
	memoryLimit    instrument.Int64UpDownCounter
	memoryGCCycles instrument.Int64Counter
	processorLimit instrument.Int64UpDownCounter
	configGOGC     instrument.Int64UpDownCounter

	memoryLimitValue    *int64
	memoryGCCyclesValue *uint64
	processorLimitValue *int64
	configGOGCValue     *int64
}

func ReportRuntimeMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	input *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AppRuntime() || input == nil {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		reporter, err := newRuntimeMetricsReporter(ctx, ctxInfo, cfg, input)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL runtime metrics reporter: %w", err)
		}

		return reporter.reportMetrics, nil
	}
}

func newRuntimeMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	input *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
) (*RuntimeMetricsReporter, error) {
	log := rmlog()

	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}

	reporter := &RuntimeMetricsReporter{
		ctx:      ctx,
		cfg:      cfg,
		nodeMeta: ctxInfo.NodeMeta,
		exporter: instrumentMetricsExporter(ctxInfo.Metrics, exporter),
		input:    input.Subscribe(msg.SubscriberName("otel.RuntimeMetricsReporter")),
		log:      log,
	}

	reporter.reporters, err = otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *RuntimeMetrics) {
			llog := log.With("service", id)
			llog.Debug("evicting runtime metrics reporter from cache")

			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted runtime metrics provider", "error", err)
				}
			}()
		}, reporter.newMetricSet)
	if err != nil {
		return nil, fmt.Errorf("creating runtime metrics reporters pool: %w", err)
	}

	return reporter, nil
}

func (r *RuntimeMetricsReporter) newMetricsInstance(service *svc.Attrs) RuntimeMetrics {
	log := r.log
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		log = log.With("service", service)
		resourceAttributes = append(otelcfg.GetAppResourceAttrs(&r.nodeMeta, service), otelcfg.ResourceAttrsFromEnv(service)...)
	}
	log.Debug("creating new runtime metrics reporter")

	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)
	provider := metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(r.exporter,
			metric.WithInterval(r.cfg.Interval))),
	)

	return RuntimeMetrics{
		ctx:      r.ctx,
		service:  service,
		provider: provider,
	}
}

func (r *RuntimeMetricsReporter) newMetricSet(service *svc.Attrs) (*RuntimeMetrics, error) {
	metrics := r.newMetricsInstance(service)
	meter := metrics.provider.Meter(reporterName)
	if err := setupRuntimeMeters(&metrics, meter); err != nil {
		return nil, err
	}
	return &metrics, nil
}

func setupRuntimeMeters(metrics *RuntimeMetrics, meter instrument.Meter) error {
	return setupGoRuntimeMeters(&metrics.goMetrics, meter)
}

func setupGoRuntimeMeters(metrics *goRuntimeMetrics, meter instrument.Meter) error {
	var err error
	metrics.memoryLimit, err = meter.Int64UpDownCounter(attributes.GoRuntimeMemoryLimit.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating go memory limit: %w", err)
	}
	metrics.memoryGCCycles, err = meter.Int64Counter(attributes.GoRuntimeMemoryGCCycles.OTEL, instrument.WithUnit("{gc_cycle}"))
	if err != nil {
		return fmt.Errorf("creating go memory gc cycles: %w", err)
	}
	metrics.processorLimit, err = meter.Int64UpDownCounter(attributes.GoRuntimeProcessorLimit.OTEL, instrument.WithUnit("{thread}"))
	if err != nil {
		return fmt.Errorf("creating go processor limit: %w", err)
	}
	metrics.configGOGC, err = meter.Int64UpDownCounter(attributes.GoRuntimeConfigGOGC.OTEL, instrument.WithUnit("%"))
	if err != nil {
		return fmt.Errorf("creating go config gogc: %w", err)
	}

	return nil
}

func (r *RuntimeMetricsReporter) reportMetrics(ctx context.Context) {
	defer r.close()

	for {
		select {
		case <-ctx.Done():
			r.log.Debug("context done, stopping runtime metrics reporting")
			return
		case snapshots, ok := <-r.input:
			if !ok {
				r.log.Debug("runtime metrics input channel closed, stopping metrics reporting")
				return
			}
			r.reportRuntimeMetrics(snapshots)
		}
	}
}

func (r *RuntimeMetricsReporter) reportRuntimeMetrics(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	for _, snapshot := range snapshots {
		metrics, err := r.reporters.For(&snapshot.Service)
		if err != nil {
			r.log.Debug("creating runtime metric set failed", "pid", snapshot.PID, "error", err)
			continue
		}
		recordRuntimeMetrics(r.ctx, metrics, snapshot)
	}
}

func recordRuntimeMetrics(ctx context.Context, metrics *RuntimeMetrics, snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if metrics == nil {
		return
	}

	if snapshot.Service.SDKLanguage != svc.InstrumentableGolang {
		return
	}
	recordGoRuntimeMetrics(ctx, &metrics.goMetrics, snapshot)
}

func recordGoRuntimeMetrics(ctx context.Context, metrics *goRuntimeMetrics, snapshot runtimemetrics.RuntimeMetricSnapshot) {
	recordCurrentRuntimeMetric(ctx, metrics.memoryLimit, &metrics.memoryLimitValue, snapshot.MemoryLimit)
	recordRuntimeCounter(ctx, metrics.memoryGCCycles, &metrics.memoryGCCyclesValue, snapshot.GCCycles)
	recordCurrentRuntimeMetric(ctx, metrics.processorLimit, &metrics.processorLimitValue, snapshot.ProcessorLimit)
	recordCurrentRuntimeMetric(ctx, metrics.configGOGC, &metrics.configGOGCValue, snapshot.GOGC)
}

func recordCurrentRuntimeMetric(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	previous **int64,
	current *int64,
) {
	if current == nil {
		if *previous != nil {
			metric.Add(ctx, -**previous)
			*previous = nil
		}
		metric.Remove(ctx)
		return
	}

	if *previous == nil {
		metric.Add(ctx, *current)
	} else if delta := *current - **previous; delta != 0 {
		metric.Add(ctx, delta)
	}
	value := *current
	*previous = &value
}

func recordRuntimeCounter(
	ctx context.Context,
	metric instrument.Int64Counter,
	previous **uint64,
	current *uint64,
) {
	if current == nil {
		*previous = nil
		metric.Remove(ctx)
		return
	}

	if *previous == nil || *current < **previous {
		metric.Remove(ctx)
		metric.Add(ctx, int64(*current))
	} else if delta := *current - **previous; delta > 0 {
		metric.Add(ctx, int64(delta))
	}
	value := *current
	*previous = &value
}

func (r *RuntimeMetricsReporter) close() {
	go func() {
		if err := r.exporter.Shutdown(r.ctx); err != nil {
			rmlog().Warn("closing runtime metrics provider", "error", err)
			return
		}
		rmlog().Debug("runtime metrics reporter closed")
	}()
}
