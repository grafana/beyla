// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type jvmRuntimeMetrics struct {
	ctx                   context.Context
	memoryUsed            *runtimeCurrentUpDownCounter
	memoryCommitted       *runtimeCurrentUpDownCounter
	memoryLimit           *runtimeCurrentUpDownCounter
	memoryUsedAfterLastGC *runtimeCurrentUpDownCounter
}

func setupJVMRuntimeMeters(ctx context.Context, m *jvmRuntimeMetrics, meter instrument.Meter, ttl time.Duration) error {
	memoryAttrs := jvmMemoryOTELAttributes()
	var err error

	m.ctx = ctx
	memoryUsed, err := meter.Int64UpDownCounter(attributes.JVMMemoryUsed.OTEL, instrument.WithUnit(attributes.JVMMemoryUsed.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM memory used up-down counter: %w", err)
	}
	m.memoryUsed = newRuntimeCurrentUpDownCounter(ctx, memoryUsed, memoryAttrs, timeNow, ttl)

	memoryCommitted, err := meter.Int64UpDownCounter(attributes.JVMMemoryCommitted.OTEL, instrument.WithUnit(attributes.JVMMemoryCommitted.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM memory committed up-down counter: %w", err)
	}
	m.memoryCommitted = newRuntimeCurrentUpDownCounter(ctx, memoryCommitted, memoryAttrs, timeNow, ttl)

	memoryLimit, err := meter.Int64UpDownCounter(attributes.JVMMemoryLimit.OTEL, instrument.WithUnit(attributes.JVMMemoryLimit.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM memory limit up-down counter: %w", err)
	}
	m.memoryLimit = newRuntimeCurrentUpDownCounter(ctx, memoryLimit, memoryAttrs, timeNow, ttl)

	memoryUsedAfterLastGC, err := meter.Int64UpDownCounter(attributes.JVMMemoryUsedAfterLastGC.OTEL, instrument.WithUnit(attributes.JVMMemoryUsedAfterLastGC.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM memory used after last GC up-down counter: %w", err)
	}
	m.memoryUsedAfterLastGC = newRuntimeCurrentUpDownCounter(ctx, memoryUsedAfterLastGC, memoryAttrs, timeNow, ttl)

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
