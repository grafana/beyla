// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"math/bits"
	"sync"
	"time"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeHistogramProducer struct {
	mu           sync.Mutex
	temporality  metricdata.Temporality
	histograms   map[goRuntimeHistogramKey]goRuntimeHistogramState
	lastProduced map[goRuntimeHistogramKey]goRuntimeHistogramState
	pendingFinal map[runtimemetrics.GoHistogramKind][]goRuntimeHistogramState
	retired      map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState
}

type goRuntimeHistogramKey struct {
	kind runtimemetrics.GoHistogramKind
	pid  app.PID
}

type goRuntimeHistogramState struct {
	time      time.Time
	startTime time.Time
	histogram runtimemetrics.GoRuntimeHistogramSnapshot
}

func newGoRuntimeHistogramProducer(temporality metricdata.Temporality) *goRuntimeHistogramProducer {
	return &goRuntimeHistogramProducer{
		temporality:  temporality,
		histograms:   make(map[goRuntimeHistogramKey]goRuntimeHistogramState),
		lastProduced: make(map[goRuntimeHistogramKey]goRuntimeHistogramState),
		pendingFinal: make(map[runtimemetrics.GoHistogramKind][]goRuntimeHistogramState),
		retired:      make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState),
	}
}

func (p *goRuntimeHistogramProducer) Update(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.Histogram == nil {
		return
	}

	histogram := *snapshot.Histogram
	histogram.Counts = append([]uint64(nil), snapshot.Histogram.Counts...)
	name, err := goRuntimeHistogramMetricName(histogram.Kind)
	if err != nil {
		rmlog().Warn("skipping unsupported Go runtime histogram",
			"pid", snapshot.PID,
			"kind", histogram.Kind,
			"error", err)
		return
	}
	if _, err := histogram.Data(); err != nil {
		rmlog().Warn("skipping malformed Go runtime histogram",
			"pid", snapshot.PID,
			"metric", name,
			"error", err)
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	key := goRuntimeHistogramKey{kind: histogram.Kind, pid: snapshot.PID}
	previous, exists := p.histograms[key]
	startTime := previous.startTime
	if !exists || histogramPopulationRegressed(previous.histogram, histogram) {
		startTime = snapshot.Time
	}
	p.histograms[key] = goRuntimeHistogramState{
		time:      snapshot.Time,
		startTime: startTime,
		histogram: histogram,
	}
}

func (p *goRuntimeHistogramProducer) Delete(pid app.PID) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key := range p.histograms {
		if key.pid == pid {
			if p.temporality == metricdata.DeltaTemporality {
				current := map[goRuntimeHistogramKey]goRuntimeHistogramState{
					key: p.histograms[key],
				}
				previous := map[goRuntimeHistogramKey]goRuntimeHistogramState{}
				if baseline, ok := p.lastProduced[key]; ok {
					previous[key] = baseline
				}
				if delta, ok := deltaGoRuntimeHistogramStates(current, previous)[key]; ok {
					delta.histogram.Counts = append([]uint64(nil), delta.histogram.Counts...)
					p.pendingFinal[key.kind] = append(p.pendingFinal[key.kind], delta)
				}
			} else {
				aggregated := make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, 1)
				if retired, ok := p.retired[key.kind]; ok {
					aggregated[key.kind] = retired
				}
				if err := addGoRuntimeHistogramState(aggregated, key.kind, p.histograms[key]); err != nil {
					rmlog().Warn(
						"retaining active Go runtime histogram after failed retirement",
						"kind", key.kind,
						"pid", pid,
						"error", err,
					)
					continue
				}
				p.retired[key.kind] = aggregated[key.kind]
			}
			delete(p.histograms, key)
			delete(p.lastProduced, key)
		}
	}
}

func histogramPopulationRegressed(
	previous runtimemetrics.GoRuntimeHistogramSnapshot,
	current runtimemetrics.GoRuntimeHistogramSnapshot,
) bool {
	if previous.Underflow > current.Underflow || previous.Overflow > current.Overflow ||
		len(previous.Counts) != len(current.Counts) {
		return true
	}
	for i, population := range previous.Counts {
		if population > current.Counts[i] {
			return true
		}
	}
	return false
}

func (p *goRuntimeHistogramProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	current := cloneGoRuntimeHistogramStates(p.histograms)
	states := current
	if p.temporality == metricdata.DeltaTemporality {
		states = deltaGoRuntimeHistogramStates(current, p.lastProduced)
	}
	aggregated, err := aggregateGoRuntimeHistogramStates(states)
	if err != nil {
		return nil, err
	}
	for kind, state := range p.retired {
		if err := addGoRuntimeHistogramState(aggregated, kind, state); err != nil {
			return nil, err
		}
	}
	for kind, states := range p.pendingFinal {
		for _, state := range states {
			if err := addGoRuntimeHistogramState(aggregated, kind, state); err != nil {
				return nil, err
			}
		}
	}
	if len(aggregated) == 0 {
		return nil, nil
	}

	metrics := make([]metricdata.Metrics, 0, len(aggregated))
	for _, kind := range []runtimemetrics.GoHistogramKind{
		runtimemetrics.GoHistogramKindGCPause,
		runtimemetrics.GoHistogramKindSchedLatency,
	} {
		state, ok := aggregated[kind]
		if !ok {
			continue
		}
		metric, err := produceGoRuntimeHistogram(kind, state, p.temporality)
		if err != nil {
			return nil, err
		}
		metrics = append(metrics, metric)
		delete(aggregated, kind)
	}
	for kind := range aggregated {
		return nil, fmt.Errorf("producing Go runtime histogram kind %d: unsupported kind", kind)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.temporality == metricdata.DeltaTemporality {
		p.lastProduced = current
		clear(p.pendingFinal)
	}

	return []metricdata.ScopeMetrics{{
		Scope:   instrumentation.Scope{Name: reporterName},
		Metrics: metrics,
	}}, nil
}

func cloneGoRuntimeHistogramStates(
	states map[goRuntimeHistogramKey]goRuntimeHistogramState,
) map[goRuntimeHistogramKey]goRuntimeHistogramState {
	cloned := make(map[goRuntimeHistogramKey]goRuntimeHistogramState, len(states))
	for key, state := range states {
		state.histogram.Counts = append([]uint64(nil), state.histogram.Counts...)
		cloned[key] = state
	}
	return cloned
}

func deltaGoRuntimeHistogramStates(
	current map[goRuntimeHistogramKey]goRuntimeHistogramState,
	previous map[goRuntimeHistogramKey]goRuntimeHistogramState,
) map[goRuntimeHistogramKey]goRuntimeHistogramState {
	deltas := make(map[goRuntimeHistogramKey]goRuntimeHistogramState, len(current))
	for key, state := range current {
		baseline, exists := previous[key]
		if !exists ||
			baseline.startTime != state.startTime ||
			histogramPopulationRegressed(baseline.histogram, state.histogram) {
			deltas[key] = state
			continue
		}

		state.startTime = baseline.time
		state.histogram.Underflow -= baseline.histogram.Underflow
		state.histogram.Overflow -= baseline.histogram.Overflow
		// current's Counts must stay cumulative: it becomes the next baseline.
		counts := make([]uint64, len(state.histogram.Counts))
		var changed bool
		for i := range counts {
			counts[i] = state.histogram.Counts[i] - baseline.histogram.Counts[i]
			changed = changed || counts[i] != 0
		}
		state.histogram.Counts = counts
		if changed || state.histogram.Underflow != 0 || state.histogram.Overflow != 0 {
			deltas[key] = state
		}
	}
	return deltas
}

func aggregateGoRuntimeHistogramStates(
	states map[goRuntimeHistogramKey]goRuntimeHistogramState,
) (map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState, error) {
	aggregated := make(map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState)
	for key, state := range states {
		if err := addGoRuntimeHistogramState(aggregated, key.kind, state); err != nil {
			return nil, err
		}
	}
	return aggregated, nil
}

func addGoRuntimeHistogramState(
	aggregated map[runtimemetrics.GoHistogramKind]goRuntimeHistogramState,
	kind runtimemetrics.GoHistogramKind,
	state goRuntimeHistogramState,
) error {
	current, exists := aggregated[kind]
	if !exists {
		state.histogram.Counts = append([]uint64(nil), state.histogram.Counts...)
		aggregated[kind] = state
		return nil
	}
	if len(current.histogram.Counts) != len(state.histogram.Counts) {
		return fmt.Errorf("aggregating Go runtime histogram kind %d: population count mismatch", kind)
	}
	if state.startTime.Before(current.startTime) {
		current.startTime = state.startTime
	}
	if state.time.After(current.time) {
		current.time = state.time
	}

	current.histogram.Counts = append([]uint64(nil), current.histogram.Counts...)
	var carry uint64
	current.histogram.Underflow, carry = bits.Add64(
		current.histogram.Underflow,
		state.histogram.Underflow,
		0,
	)
	if carry != 0 {
		return fmt.Errorf("aggregating Go runtime histogram kind %d: population overflow", kind)
	}
	current.histogram.Overflow, carry = bits.Add64(
		current.histogram.Overflow,
		state.histogram.Overflow,
		0,
	)
	if carry != 0 {
		return fmt.Errorf("aggregating Go runtime histogram kind %d: population overflow", kind)
	}
	for i, population := range state.histogram.Counts {
		current.histogram.Counts[i], carry = bits.Add64(current.histogram.Counts[i], population, 0)
		if carry != 0 {
			return fmt.Errorf("aggregating Go runtime histogram kind %d: population overflow", kind)
		}
	}
	aggregated[kind] = current
	return nil
}

func produceGoRuntimeHistogram(
	kind runtimemetrics.GoHistogramKind,
	state goRuntimeHistogramState,
	temporality metricdata.Temporality,
) (metricdata.Metrics, error) {
	name, err := goRuntimeHistogramMetricName(kind)
	if err != nil {
		return metricdata.Metrics{}, err
	}
	data, err := state.histogram.Data()
	if err != nil {
		return metricdata.Metrics{}, fmt.Errorf("converting %s histogram: %w", name, err)
	}

	return metricdata.Metrics{
		Name: name,
		Unit: "s",
		Data: metricdata.Histogram[float64]{
			Temporality: temporality,
			DataPoints: []metricdata.HistogramDataPoint[float64]{
				{
					StartTime:    state.startTime,
					Time:         state.time,
					Count:        data.Count,
					Bounds:       data.Bounds,
					BucketCounts: data.BucketCounts,
					Sum:          data.Sum,
				},
			},
		},
	}, nil
}

func goRuntimeHistogramMetricName(kind runtimemetrics.GoHistogramKind) (string, error) {
	switch kind {
	case runtimemetrics.GoHistogramKindGCPause:
		return attributes.GoRuntimeMemoryGCPauseDuration.OTEL, nil
	case runtimemetrics.GoHistogramKindSchedLatency:
		return attributes.GoRuntimeScheduleDuration.OTEL, nil
	default:
		return "", fmt.Errorf("producing Go runtime histogram kind %d: unsupported kind", kind)
	}
}
