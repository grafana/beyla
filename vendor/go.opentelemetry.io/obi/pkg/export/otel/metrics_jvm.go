// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

type JVMRuntimeMetricsReporter struct {
	ctx             context.Context
	cfg             *otelcfg.MetricsConfig
	nodeMeta        meta.NodeMeta
	exporter        sdkmetric.Exporter
	reporters       otelcfg.ReporterPool[*svc.Attrs, *jvmRuntimeMetrics]
	jointMetricsCfg *perapp.MetricsConfig
	input           <-chan []jvmruntime.JVMRuntimeEvent
	log             *slog.Logger
}

type jvmRuntimeMetrics struct {
	ctx                   context.Context
	service               *svc.Attrs
	provider              *metric.MeterProvider
	memoryUsed            *jvmCurrentUpDownCounter
	memoryCommitted       *jvmCurrentUpDownCounter
	memoryLimit           *jvmCurrentUpDownCounter
	memoryUsedAfterLastGC *jvmCurrentUpDownCounter
	beylaJVMHeapUsed      *Expirer[jvmruntime.JVMRuntimeEvent, instrument.Int64Gauge, int64]
}

type jvmCurrentUpDownCounter struct {
	ctx     context.Context
	metric  instrument.Int64UpDownCounter
	attrs   []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue]
	entries *expire.ExpiryMap[*jvmCurrentUpDownCounterEntry]
	log     *slog.Logger

	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

type jvmCurrentUpDownCounterEntry struct {
	attrs       attribute.Set
	value       int64
	initialized bool
}

func ReportJVMRuntimeMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsCfg *perapp.MetricsConfig,
	input *msg.Queue[[]jvmruntime.JVMRuntimeEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if input == nil || !(cfg.EndpointEnabled() && jointMetricsCfg.Features.AppJVM()) {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		reporter, err := newJVMRuntimeMetricsReporter(ctx, ctxInfo, cfg, jointMetricsCfg)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL JVM runtime metrics reporter: %w", err)
		}
		reporter.input = input.Subscribe(msg.SubscriberName("otel.JVMRuntimeMetrics"))
		return reporter.reportMetrics, nil
	}
}

func newJVMRuntimeMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsCfg *perapp.MetricsConfig,
) (*JVMRuntimeMetricsReporter, error) {
	mr := &JVMRuntimeMetricsReporter{
		ctx:             ctx,
		cfg:             cfg,
		nodeMeta:        ctxInfo.NodeMeta,
		jointMetricsCfg: jointMetricsCfg,
		log:             slog.With("component", "otel.JVMRuntimeMetricsReporter"),
	}

	reporters, err := otelcfg.NewReporterPool[*svc.Attrs, *jvmRuntimeMetrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(id svc.UID, v *jvmRuntimeMetrics) {
			if err := v.provider.Shutdown(ctx); err != nil {
				mr.log.Warn("error shutting down evicted JVM runtime metrics provider", "service", id, "error", err)
			}
		}, mr.newMetricSet)
	if err != nil {
		return nil, fmt.Errorf("creating JVM runtime metrics reporters pool: %w", err)
	}
	mr.reporters = reporters

	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}
	mr.exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	return mr, nil
}

func (mr *JVMRuntimeMetricsReporter) reportMetrics(ctx context.Context) {
	defer mr.close()
	for {
		select {
		case <-ctx.Done():
			mr.log.Debug("context done, stopping JVM runtime metrics reporting")
			return
		case events, ok := <-mr.input:
			if !ok {
				mr.log.Debug("input channel closed, stopping JVM runtime metrics reporting")
				return
			}
			for i := range events {
				mr.observe(events[i])
			}
		}
	}
}

func (mr *JVMRuntimeMetricsReporter) observe(event jvmruntime.JVMRuntimeEvent) {
	if !event.Service.ExportModes.CanExportMetrics() || !event.Service.Features.AppJVM() {
		return
	}
	metrics, err := mr.reporters.For(&event.Service)
	if err != nil {
		mr.log.Warn("dropping JVM runtime metric, can't get service metric set", "error", err)
		return
	}
	metrics.record(event)
}

func (mr *JVMRuntimeMetricsReporter) newMetricSet(service *svc.Attrs) (*jvmRuntimeMetrics, error) {
	m := mr.newMetricsInstance(service)
	meter := m.provider.Meter(reporterName)
	if err := setupJVMRuntimeMeters(mr.ctx, m, meter, mr.cfg.TTL); err != nil {
		return nil, err
	}
	return m, nil
}

func (mr *JVMRuntimeMetricsReporter) newMetricsInstance(service *svc.Attrs) *jvmRuntimeMetrics {
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		resourceAttributes = append(otelcfg.GetAppResourceAttrs(&mr.nodeMeta, service), otelcfg.ResourceAttrsFromEnv(service)...)
	}
	resources := resource.NewWithAttributes(semconv.SchemaURL, resourceAttributes...)
	return &jvmRuntimeMetrics{
		ctx:     mr.ctx,
		service: service,
		provider: metric.NewMeterProvider(
			metric.WithResource(resources),
			metric.WithReader(metric.NewPeriodicReader(sharedExporter{mr.exporter}, metric.WithInterval(mr.cfg.Interval))),
		),
	}
}

func setupJVMRuntimeMeters(ctx context.Context, m *jvmRuntimeMetrics, meter instrument.Meter, ttl time.Duration) error {
	memoryAttrs := jvmMemoryOTELAttributes()
	heapAttrs := jvmHeapOTELAttributes()
	var err error

	memoryUsed, err := meter.Int64UpDownCounter(attributes.JVMMemoryUsed.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating JVM memory used up-down counter: %w", err)
	}
	m.memoryUsed = newJVMCurrentUpDownCounter(ctx, memoryUsed, memoryAttrs, timeNow, ttl)

	memoryCommitted, err := meter.Int64UpDownCounter(attributes.JVMMemoryCommitted.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating JVM memory committed up-down counter: %w", err)
	}
	m.memoryCommitted = newJVMCurrentUpDownCounter(ctx, memoryCommitted, memoryAttrs, timeNow, ttl)

	memoryLimit, err := meter.Int64UpDownCounter(attributes.JVMMemoryLimit.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating JVM memory limit up-down counter: %w", err)
	}
	m.memoryLimit = newJVMCurrentUpDownCounter(ctx, memoryLimit, memoryAttrs, timeNow, ttl)

	memoryUsedAfterLastGC, err := meter.Int64UpDownCounter(attributes.JVMMemoryUsedAfterLastGC.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating JVM memory used after last GC up-down counter: %w", err)
	}
	m.memoryUsedAfterLastGC = newJVMCurrentUpDownCounter(ctx, memoryUsedAfterLastGC, memoryAttrs, timeNow, ttl)

	heapUsed, err := meter.Int64Gauge(attributes.BeylaJVMHeapUsed.OTEL, instrument.WithUnit("By"))
	if err != nil {
		return fmt.Errorf("creating Beyla JVM heap used gauge: %w", err)
	}
	m.beylaJVMHeapUsed = NewExpirer[jvmruntime.JVMRuntimeEvent, instrument.Int64Gauge, int64](ctx, heapUsed, heapAttrs, timeNow, ttl)

	return nil
}

func (m *jvmRuntimeMetrics) record(event jvmruntime.JVMRuntimeEvent) {
	ctx := m.ctx
	value := int64(event.ValueBytes)
	switch event.Kind {
	case jvmruntime.JVMMetricMemoryUsed:
		m.memoryUsed.Record(event, value)
	case jvmruntime.JVMMetricMemoryCommitted:
		m.memoryCommitted.Record(event, value)
	case jvmruntime.JVMMetricMemoryLimit:
		m.memoryLimit.Record(event, value)
	case jvmruntime.JVMMetricMemoryUsedAfterLastGC:
		m.memoryUsedAfterLastGC.Record(event, value)
	case jvmruntime.JVMMetricBeylaHeapUsed:
		gauge, attrs := m.beylaJVMHeapUsed.ForRecord(event)
		gauge.Record(ctx, value, instrument.WithAttributeSet(attrs))
	}
}

func newJVMCurrentUpDownCounter(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	attrs []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue],
	clock expire.Clock,
	ttl time.Duration,
) *jvmCurrentUpDownCounter {
	return &jvmCurrentUpDownCounter{
		ctx:            ctx,
		metric:         metric,
		attrs:          attrs,
		entries:        expire.NewExpiryMap[*jvmCurrentUpDownCounterEntry](clock, ttl),
		log:            plog().With("type", fmt.Sprintf("%T", metric)),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            ttl,
	}
}

func (c *jvmCurrentUpDownCounter) Record(event jvmruntime.JVMRuntimeEvent, value int64) {
	now := c.clock()
	if now.Sub(c.lastExpiration) >= c.ttl {
		c.removeOutdated(c.ctx)
		c.lastExpiration = now
	}

	recordAttrs, attrValues := jvmRuntimeAttributeSet(c.attrs, event)
	entry := c.entries.GetOrCreate(attrValues, func() *jvmCurrentUpDownCounterEntry {
		c.log.Debug("storing new metric label set", "labelValues", attrValues)
		return &jvmCurrentUpDownCounterEntry{attrs: recordAttrs}
	})

	delta := value - entry.value
	if !entry.initialized || delta != 0 {
		c.metric.Add(c.ctx, delta, instrument.WithAttributeSet(entry.attrs))
	}
	entry.value = value
	entry.initialized = true
}

func (c *jvmCurrentUpDownCounter) removeOutdated(ctx context.Context) {
	for _, entry := range c.entries.DeleteExpired() {
		c.metric.Add(ctx, -entry.value, instrument.WithAttributeSet(entry.attrs))
		c.metric.Remove(ctx, instrument.WithAttributeSet(entry.attrs))
	}
}

func jvmRuntimeAttributeSet(
	fields []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue],
	event jvmruntime.JVMRuntimeEvent,
) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(fields))
	vals := make([]string, 0, len(fields))

	for _, field := range fields {
		kv := field.Get(event)
		keyVals = append(keyVals, kv)
		vals = append(vals, kv.Value.Emit())
	}

	return attribute.NewSet(keyVals...), vals
}

func (mr *JVMRuntimeMetricsReporter) close() {
	go func() {
		if err := mr.exporter.Shutdown(mr.ctx); err != nil {
			mr.log.Warn("closing JVM runtime metrics exporter", "error", err)
		}
	}()
}

func jvmMemoryOTELAttributes() []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue] {
	return []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue]{
		{
			ExposedName: string(attr.JVMMemoryType.OTEL()),
			Get: func(event jvmruntime.JVMRuntimeEvent) attribute.KeyValue {
				return attr.JVMMemoryType.OTEL().String(string(event.MemoryType))
			},
		},
		{
			ExposedName: string(attr.JVMMemoryPoolName.OTEL()),
			Get: func(event jvmruntime.JVMRuntimeEvent) attribute.KeyValue {
				return attr.JVMMemoryPoolName.OTEL().String(event.PoolName)
			},
		},
	}
}

func jvmHeapOTELAttributes() []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue] {
	return []attributes.Field[jvmruntime.JVMRuntimeEvent, attribute.KeyValue]{
		{
			ExposedName: string(attr.JVMGCPhase.OTEL()),
			Get: func(event jvmruntime.JVMRuntimeEvent) attribute.KeyValue {
				return attr.JVMGCPhase.OTEL().String(string(event.GCPhase))
			},
		},
	}
}
