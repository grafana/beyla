// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/attribute"

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
	return nil
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
