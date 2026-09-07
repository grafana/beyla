// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app"
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
	classLoaded           instrument.Int64Counter
	classUnloaded         instrument.Int64Counter
	classCount            *runtimeCurrentUpDownCounter
	daemonThreadCount     *runtimeCurrentUpDownCounter
	nonDaemonThreadCount  *runtimeCurrentUpDownCounter
	cpuTime               instrument.Float64Counter
	cpuCount              *runtimeCurrentUpDownCounter
	cpuRecentUtilization  instrument.Float64Gauge
	runtimeEntries        map[jvmRuntimeEntryKey]*jvmRuntimeEntry
}

type jvmRuntimeEntryKey struct {
	pid        app.PID
	generation uint64
}

type jvmRuntimeEntry struct {
	classLoaded   *uint64
	classUnloaded *uint64
	cpuTime       *int64
}

func setupJVMRuntimeMeters(ctx context.Context, m *jvmRuntimeMetrics, meter instrument.Meter, ttl time.Duration) error {
	memoryAttrs := jvmMemoryOTELAttributes()
	var err error

	m.ctx = ctx
	m.runtimeEntries = map[jvmRuntimeEntryKey]*jvmRuntimeEntry{}
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

	// Class loading
	if m.classLoaded, err = meter.Int64Counter(attributes.JVMClassLoaded.OTEL, instrument.WithUnit(attributes.JVMClassLoaded.Unit)); err != nil {
		return fmt.Errorf("creating JVM class loaded counter: %w", err)
	}
	if m.classUnloaded, err = meter.Int64Counter(attributes.JVMClassUnloaded.OTEL, instrument.WithUnit(attributes.JVMClassUnloaded.Unit)); err != nil {
		return fmt.Errorf("creating JVM class unloaded counter: %w", err)
	}
	classCount, err := meter.Int64UpDownCounter(attributes.JVMClassCount.OTEL, instrument.WithUnit(attributes.JVMClassCount.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM class count up-down counter: %w", err)
	}
	m.classCount = newRuntimeCurrentUpDownCounter(ctx, classCount, nil, timeNow, ttl)

	// Platform threads
	threadCount, err := meter.Int64UpDownCounter(attributes.JVMThreadCount.OTEL, instrument.WithUnit(attributes.JVMThreadCount.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM thread count up-down counter: %w", err)
	}
	m.daemonThreadCount = newRuntimeCurrentUpDownCounter(ctx, threadCount, jvmThreadOTELAttributes(true), timeNow, ttl)
	m.nonDaemonThreadCount = newRuntimeCurrentUpDownCounter(ctx, threadCount, jvmThreadOTELAttributes(false), timeNow, ttl)

	// Process CPU
	if m.cpuTime, err = meter.Float64Counter(attributes.JVMCPUTime.OTEL, instrument.WithUnit(attributes.JVMCPUTime.Unit)); err != nil {
		return fmt.Errorf("creating JVM CPU time counter: %w", err)
	}
	cpuCount, err := meter.Int64UpDownCounter(attributes.JVMCPUCount.OTEL, instrument.WithUnit(attributes.JVMCPUCount.Unit))
	if err != nil {
		return fmt.Errorf("creating JVM CPU count up-down counter: %w", err)
	}
	m.cpuCount = newRuntimeCurrentUpDownCounter(ctx, cpuCount, nil, timeNow, ttl)
	if m.cpuRecentUtilization, err = meter.Float64Gauge(
		attributes.JVMCPURecentUtilization.OTEL,
		instrument.WithUnit(attributes.JVMCPURecentUtilization.Unit)); err != nil {
		return fmt.Errorf("creating JVM recent CPU utilization gauge: %w", err)
	}

	return nil
}

func (m *jvmRuntimeMetrics) record(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.JVM == nil {
		return
	}
	if values := snapshot.JVM.RuntimeValues; values != nil {
		key := jvmRuntimeEntryKey{
			pid:        snapshot.Service.ProcPID,
			generation: snapshot.Generation,
		}
		entry := m.runtimeEntries[key]
		if entry == nil {
			entry = &jvmRuntimeEntry{}
			m.runtimeEntries[key] = entry
		}
		recordJVMRuntimeCounter(m.ctx, m.classLoaded, &entry.classLoaded, values.TotalLoadedClassCount)
		recordJVMRuntimeCounter(m.ctx, m.classUnloaded, &entry.classUnloaded, values.UnloadedClassCount)
		m.classCount.Record(snapshot, int64(values.LoadedClassCount))

		daemonThreads := values.DaemonThreadCount
		if daemonThreads > values.ThreadCount {
			daemonThreads = values.ThreadCount
		}
		m.daemonThreadCount.Record(snapshot, int64(daemonThreads))
		m.nonDaemonThreadCount.Record(snapshot, int64(values.ThreadCount-daemonThreads))

		if values.ProcessCPUTimeNS >= 0 {
			recordJVMRuntimeFloatCounter(m.ctx, m.cpuTime, &entry.cpuTime, values.ProcessCPUTimeNS)
		}
		m.cpuCount.Record(snapshot, int64(values.AvailableProcessorCount))
		if values.RecentCPUUtilization >= 0 && values.RecentCPUUtilization <= 1 {
			m.cpuRecentUtilization.Record(m.ctx, values.RecentCPUUtilization)
		} else {
			m.cpuRecentUtilization.Remove(m.ctx)
		}
		return
	}
	if m.memoryUsed == nil {
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

func (m *jvmRuntimeMetrics) deleteProcess(pid app.PID, generation uint64) {
	delete(m.runtimeEntries, jvmRuntimeEntryKey{pid: pid, generation: generation})
}

func recordJVMRuntimeCounter(
	ctx context.Context,
	metric instrument.Int64Counter,
	previous **uint64,
	current uint64,
) {
	delta := current
	if *previous != nil && current >= **previous {
		delta = current - **previous
	}
	if delta > 0 {
		metric.Add(ctx, int64(delta))
	}

	value := current
	*previous = &value
}

func recordJVMRuntimeFloatCounter(
	ctx context.Context,
	metric instrument.Float64Counter,
	previous **int64,
	current int64,
) {
	delta := current
	if *previous != nil && current >= **previous {
		delta = current - **previous
	}
	if delta > 0 {
		metric.Add(ctx, float64(delta)/float64(time.Second))
	}

	value := current
	*previous = &value
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

func jvmThreadOTELAttributes(daemon bool) []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue] {
	return []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue]{
		{
			ExposedName: string(attr.JVMThreadDaemon.OTEL()),
			Get: func(runtimemetrics.RuntimeMetricSnapshot) attribute.KeyValue {
				return attr.JVMThreadDaemon.OTEL().Bool(daemon)
			},
		},
	}
}
