// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type jvmRuntimeMetrics struct {
	ctx                   context.Context
	memoryUsed            *jvmCurrentUpDownCounter
	memoryCommitted       *jvmCurrentUpDownCounter
	memoryLimit           *jvmCurrentUpDownCounter
	memoryUsedAfterLastGC *jvmCurrentUpDownCounter
}

type jvmCurrentUpDownCounter struct {
	ctx     context.Context
	metric  instrument.Int64UpDownCounter
	attrs   []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue]
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

func setupJVMRuntimeMeters(ctx context.Context, m *jvmRuntimeMetrics, meter instrument.Meter, ttl time.Duration) error {
	memoryAttrs := jvmMemoryOTELAttributes()
	var err error

	m.ctx = ctx
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

	return nil
}

func (m *jvmRuntimeMetrics) record(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.JVM == nil || m.memoryUsed == nil {
		return
	}

	value := int64(snapshot.JVM.ValueBytes)
	switch snapshot.JVM.Kind {
	case jvmruntime.JVMMetricMemoryUsed:
		m.memoryUsed.Record(snapshot, value)
	case jvmruntime.JVMMetricMemoryCommitted:
		m.memoryCommitted.Record(snapshot, value)
	case jvmruntime.JVMMetricMemoryLimit:
		m.memoryLimit.Record(snapshot, value)
	case jvmruntime.JVMMetricMemoryUsedAfterLastGC:
		m.memoryUsedAfterLastGC.Record(snapshot, value)
	}
}

func newJVMCurrentUpDownCounter(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	attrs []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue],
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

func (c *jvmCurrentUpDownCounter) Record(snapshot runtimemetrics.RuntimeMetricSnapshot, value int64) {
	now := c.clock()
	if now.Sub(c.lastExpiration) >= c.ttl {
		c.removeOutdated(c.ctx)
		c.lastExpiration = now
	}

	recordAttrs, attrValues := jvmRuntimeAttributeSet(c.attrs, snapshot)
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
	fields []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue],
	snapshot runtimemetrics.RuntimeMetricSnapshot,
) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(fields))
	vals := make([]string, 0, len(fields))

	for _, field := range fields {
		kv := field.Get(snapshot)
		keyVals = append(keyVals, kv)
		vals = append(vals, kv.Value.Emit())
	}

	return attribute.NewSet(keyVals...), vals
}

func jvmMemoryOTELAttributes() []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue] {
	return []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue]{
		{
			ExposedName: string(attr.JVMMemoryType.OTEL()),
			Get: func(snapshot runtimemetrics.RuntimeMetricSnapshot) attribute.KeyValue {
				return attr.JVMMemoryType.OTEL().String(string(snapshot.JVM.MemoryType))
			},
		},
		{
			ExposedName: string(attr.JVMMemoryPoolName.OTEL()),
			Get: func(snapshot runtimemetrics.RuntimeMetricSnapshot) attribute.KeyValue {
				return attr.JVMMemoryPoolName.OTEL().String(snapshot.JVM.PoolName)
			},
		},
	}
}
