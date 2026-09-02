// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"

	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const nanosPerSecond = 1e9

type nodejsRuntimeMetrics struct {
	ctx context.Context

	eventLoopTime        instrument.Float64Counter
	eventLoopUtilization instrument.Float64Gauge
	delayMin             instrument.Float64Gauge
	delayMax             instrument.Float64Gauge
	delayMean            instrument.Float64Gauge
	delayStddev          instrument.Float64Gauge
	delayP50             instrument.Float64Gauge
	delayP90             instrument.Float64Gauge
	delayP99             instrument.Float64Gauge

	gcDuration  instrument.Float64Histogram
	gcTypeAttrs map[nodejsruntime.NodejsGCType]attribute.Set

	heapLimit     *runtimeCurrentUpDownCounter
	heapUsed      *runtimeCurrentUpDownCounter
	heapAvailable *runtimeCurrentUpDownCounter
	heapPhysical  *runtimeCurrentUpDownCounter

	// ELU counters are cumulative per event loop; deltas are tracked per PID
	// so several node processes of the same service don't corrupt each other.
	entries        *expire.ExpiryMap[*nodejsEventLoopEntry]
	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

type nodejsEventLoopEntry struct {
	idleAttrs   attribute.Set
	activeAttrs attribute.Set
	idleNs      uint64
	activeNs    uint64
	initialized bool
}

func setupNodejsRuntimeMeters(
	ctx context.Context,
	m *nodejsRuntimeMetrics,
	meter instrument.Meter,
	ttl time.Duration,
	buckets export.Buckets,
) error {
	m.ctx = ctx
	m.entries = expire.NewExpiryMap[*nodejsEventLoopEntry](timeNow, ttl)
	m.clock = timeNow
	m.lastExpiration = timeNow()
	m.ttl = ttl

	var err error
	if m.eventLoopTime, err = meter.Float64Counter(
		attributes.NodejsEventLoopTime.OTEL,
		instrument.WithUnit(attributes.NodejsEventLoopTime.Unit)); err != nil {
		return fmt.Errorf("creating nodejs eventloop time counter: %w", err)
	}
	if m.eventLoopUtilization, err = meter.Float64Gauge(
		attributes.NodejsEventLoopUtilization.OTEL,
		instrument.WithUnit(attributes.NodejsEventLoopUtilization.Unit)); err != nil {
		return fmt.Errorf("creating nodejs eventloop utilization gauge: %w", err)
	}

	delayGauges := []struct {
		dst  *instrument.Float64Gauge
		name attributes.Name
	}{
		{&m.delayMin, attributes.NodejsEventLoopDelayMin},
		{&m.delayMax, attributes.NodejsEventLoopDelayMax},
		{&m.delayMean, attributes.NodejsEventLoopDelayMean},
		{&m.delayStddev, attributes.NodejsEventLoopDelayStddev},
		{&m.delayP50, attributes.NodejsEventLoopDelayP50},
		{&m.delayP90, attributes.NodejsEventLoopDelayP90},
		{&m.delayP99, attributes.NodejsEventLoopDelayP99},
	}
	for _, g := range delayGauges {
		if *g.dst, err = meter.Float64Gauge(g.name.OTEL, instrument.WithUnit(g.name.Unit)); err != nil {
			return fmt.Errorf("creating nodejs eventloop delay gauge %s: %w", g.name.OTEL, err)
		}
	}

	gcHistogramOpts := []instrument.Float64HistogramOption{
		instrument.WithUnit(attributes.V8JSGCDuration.Unit),
	}
	if len(buckets.V8JSGCDurationHistogram) > 0 {
		gcHistogramOpts = append(gcHistogramOpts,
			instrument.WithExplicitBucketBoundaries(buckets.V8JSGCDurationHistogram...))
	}
	if m.gcDuration, err = meter.Float64Histogram(
		attributes.V8JSGCDuration.OTEL, gcHistogramOpts...); err != nil {
		return fmt.Errorf("creating v8js gc duration histogram: %w", err)
	}
	gcType := attr.V8JSGCType.OTEL()
	m.gcTypeAttrs = make(map[nodejsruntime.NodejsGCType]attribute.Set)
	for _, t := range []nodejsruntime.NodejsGCType{
		nodejsruntime.NodejsGCTypeMinor,
		nodejsruntime.NodejsGCTypeMajor,
		nodejsruntime.NodejsGCTypeIncremental,
		nodejsruntime.NodejsGCTypeWeakCB,
	} {
		m.gcTypeAttrs[t] = attribute.NewSet(gcType.String(t.String()))
	}

	heapAttrs := v8jsHeapSpaceOTELAttributes()
	heapCounters := []struct {
		dst  **runtimeCurrentUpDownCounter
		name attributes.Name
	}{
		{&m.heapLimit, attributes.V8JSMemoryHeapLimit},
		{&m.heapUsed, attributes.V8JSMemoryHeapUsed},
		{&m.heapAvailable, attributes.V8JSMemoryHeapSpaceAvailableSize},
		{&m.heapPhysical, attributes.V8JSMemoryHeapSpacePhysicalSize},
	}
	for _, c := range heapCounters {
		counter, err := meter.Int64UpDownCounter(c.name.OTEL, instrument.WithUnit(c.name.Unit))
		if err != nil {
			return fmt.Errorf("creating v8js heap up-down counter %s: %w", c.name.OTEL, err)
		}
		*c.dst = newRuntimeCurrentUpDownCounter(ctx, counter, heapAttrs, timeNow, ttl)
	}
	return nil
}

func v8jsHeapSpaceOTELAttributes() []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue] {
	return []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue]{
		{
			ExposedName: string(attr.V8JSHeapSpaceName.OTEL()),
			Get: func(snapshot runtimemetrics.RuntimeMetricSnapshot) attribute.KeyValue {
				return attr.V8JSHeapSpaceName.OTEL().String(snapshot.NodejsHeapSpace.SpaceName)
			},
		},
	}
}

// recordV8 handles the v8js snapshot variants: the gc duration histogram and
// the per-space heap up-down counters (absolute sample values converted to
// deltas by runtimeCurrentUpDownCounter, exactly like the JVM memory metrics).
func (m *nodejsRuntimeMetrics) recordV8(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.NodejsGC != nil && m.gcDuration != nil {
		attrs, ok := m.gcTypeAttrs[snapshot.NodejsGC.GCType]
		if !ok {
			return
		}
		m.gcDuration.Record(m.ctx, float64(snapshot.NodejsGC.DurationNs)/nanosPerSecond,
			instrument.WithAttributeSet(attrs))
	}

	if snapshot.NodejsHeapSpace != nil && m.heapLimit != nil {
		values := snapshot.NodejsHeapSpace.NodejsHeapSpaceValues
		m.heapLimit.Record(snapshot, int64(values.SpaceSize))
		m.heapUsed.Record(snapshot, int64(values.SpaceUsedSize))
		m.heapAvailable.Record(snapshot, int64(values.SpaceAvailableSize))
		m.heapPhysical.Record(snapshot, int64(values.PhysicalSpaceSize))
	}
}

func (m *nodejsRuntimeMetrics) record(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.Nodejs == nil || m.eventLoopTime == nil {
		return
	}

	now := m.clock()
	if now.Sub(m.lastExpiration) >= m.ttl {
		m.removeOutdated()
		m.lastExpiration = now
	}

	values := snapshot.Nodejs.NodejsEventLoopValues
	// Keyed by the host-visible pid: snapshot.PID is namespace-local, and
	// nested pid namespaces under one service instance could collide on it.
	entry := m.entries.GetOrCreate([]string{strconv.Itoa(int(snapshot.Service.ProcPID))}, func() *nodejsEventLoopEntry {
		state := attr.NodejsEventLoopState.OTEL()
		return &nodejsEventLoopEntry{
			idleAttrs:   attribute.NewSet(state.String("idle")),
			activeAttrs: attribute.NewSet(state.String("active")),
		}
	})

	idleDelta := runtimemetrics.NodejsCounterDelta(entry.initialized, entry.idleNs, values.ELUIdleNs)
	activeDelta := runtimemetrics.NodejsCounterDelta(entry.initialized, entry.activeNs, values.ELUActiveNs)
	if idleDelta > 0 {
		m.eventLoopTime.Add(m.ctx, float64(idleDelta)/nanosPerSecond,
			instrument.WithAttributeSet(entry.idleAttrs))
	}
	if activeDelta > 0 {
		m.eventLoopTime.Add(m.ctx, float64(activeDelta)/nanosPerSecond,
			instrument.WithAttributeSet(entry.activeAttrs))
	}
	if total := idleDelta + activeDelta; total > 0 {
		m.eventLoopUtilization.Record(m.ctx, float64(activeDelta)/float64(total))
	}
	entry.idleNs = values.ELUIdleNs
	entry.activeNs = values.ELUActiveNs
	entry.initialized = true

	// An empty histogram window (DelayCount == 0) means the loop never
	// yielded to the delay-probe timer (fully blocked), or a pre-16.14
	// runtime reported no count. Recording zeros would report a blocked
	// loop's worst moment as its best; keep the previous window's values.
	if values.DelayCount == 0 {
		return
	}
	m.delayMin.Record(m.ctx, float64(values.DelayMinNs)/nanosPerSecond)
	m.delayMax.Record(m.ctx, float64(values.DelayMaxNs)/nanosPerSecond)
	m.delayMean.Record(m.ctx, float64(values.DelayMeanNs)/nanosPerSecond)
	m.delayStddev.Record(m.ctx, float64(values.DelayStddevNs)/nanosPerSecond)
	m.delayP50.Record(m.ctx, float64(values.DelayP50Ns)/nanosPerSecond)
	m.delayP90.Record(m.ctx, float64(values.DelayP90Ns)/nanosPerSecond)
	m.delayP99.Record(m.ctx, float64(values.DelayP99Ns)/nanosPerSecond)
}

func (m *nodejsRuntimeMetrics) removeOutdated() {
	for _, entry := range m.entries.DeleteExpired() {
		m.eventLoopTime.Remove(m.ctx, instrument.WithAttributeSet(entry.idleAttrs))
		m.eventLoopTime.Remove(m.ctx, instrument.WithAttributeSet(entry.activeAttrs))
	}
}
