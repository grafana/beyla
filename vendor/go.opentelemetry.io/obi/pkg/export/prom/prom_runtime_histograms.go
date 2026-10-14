// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"errors"
	"math/bits"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeHistogramCollector struct {
	gcPauseDesc        *prometheus.Desc
	scheduleDesc       *prometheus.Desc
	mu                 sync.RWMutex
	histogramSnapshots map[goRuntimeHistogramKey]goRuntimeHistogramState
	retiredSnapshots   map[goRuntimeHistogramSeriesKey]goRuntimeHistogramState
}

type goRuntimeHistogramKey struct {
	kind       runtimemetrics.GoHistogramKind
	pid        app.PID
	labelTuple string
}

type goRuntimeHistogramSeriesKey struct {
	kind       runtimemetrics.GoHistogramKind
	labelTuple string
}

type goRuntimeHistogramState struct {
	labels    []string
	histogram runtimemetrics.GoRuntimeHistogramSnapshot
}

func newGoRuntimeHistogramCollector(runtimeLabelNames []string) *goRuntimeHistogramCollector {
	return &goRuntimeHistogramCollector{
		gcPauseDesc: prometheus.NewDesc(
			attributes.GoRuntimeMemoryGCPauseDuration.Prom,
			"Duration of stop-the-world Go garbage collection pauses.",
			runtimeLabelNames,
			nil,
		),
		scheduleDesc: prometheus.NewDesc(
			attributes.GoRuntimeScheduleDuration.Prom,
			"Time goroutines spend runnable before being scheduled to run.",
			runtimeLabelNames,
			nil,
		),
		histogramSnapshots: make(map[goRuntimeHistogramKey]goRuntimeHistogramState),
		retiredSnapshots:   make(map[goRuntimeHistogramSeriesKey]goRuntimeHistogramState),
	}
}

func (c *goRuntimeHistogramCollector) Update(
	pid app.PID,
	labels []string,
	histogram *runtimemetrics.GoRuntimeHistogramSnapshot,
) {
	if c == nil || histogram == nil {
		return
	}
	if pid == 0 {
		mlog().Warn("skipping Go runtime histogram with zero PID", "kind", histogram.Kind)
		return
	}
	if _, err := histogram.Data(); err != nil {
		mlog().Warn(
			"skipping malformed Go runtime histogram",
			"kind", histogram.Kind,
			"pid", pid,
			"error", err,
		)
		return
	}

	state := goRuntimeHistogramState{
		labels: append([]string(nil), labels...),
		histogram: runtimemetrics.GoRuntimeHistogramSnapshot{
			Kind:      histogram.Kind,
			Counts:    append([]uint64(nil), histogram.Counts...),
			Underflow: histogram.Underflow,
			Overflow:  histogram.Overflow,
		},
	}
	key := goRuntimeHistogramKey{
		kind:       histogram.Kind,
		pid:        pid,
		labelTuple: runtimeMetricLabelTuple(labels),
	}

	c.mu.Lock()
	c.histogramSnapshots[key] = state
	c.mu.Unlock()
}

func (c *goRuntimeHistogramCollector) DeletePID(pid app.PID) {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for key, state := range c.histogramSnapshots {
		if key.pid == pid {
			seriesKey := goRuntimeHistogramSeriesKey{kind: key.kind, labelTuple: key.labelTuple}
			if retired, exists := c.retiredSnapshots[seriesKey]; exists {
				combined, err := aggregatePromRuntimeHistogramStates(
					clonePromRuntimeHistogramState(retired),
					state,
				)
				if err == nil {
					_, err = combined.histogram.Data()
				}
				if err != nil {
					mlog().Warn(
						"retaining active Go runtime histogram after failed retirement",
						"kind", key.kind,
						"pid", pid,
						"error", err,
					)
					continue
				}
				c.retiredSnapshots[seriesKey] = combined
			} else {
				c.retiredSnapshots[seriesKey] = clonePromRuntimeHistogramState(state)
			}
			delete(c.histogramSnapshots, key)
		}
	}
}

func (c *goRuntimeHistogramCollector) Delete(labels []string) {
	if c == nil {
		return
	}

	labelTuple := runtimeMetricLabelTuple(labels)
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.histogramSnapshots {
		if key.labelTuple == labelTuple {
			delete(c.histogramSnapshots, key)
		}
	}
	for key := range c.retiredSnapshots {
		if key.labelTuple == labelTuple {
			delete(c.retiredSnapshots, key)
		}
	}
}

func (c *goRuntimeHistogramCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.gcPauseDesc
	ch <- c.scheduleDesc
}

func (c *goRuntimeHistogramCollector) Collect(ch chan<- prometheus.Metric) {
	states := c.snapshot()
	for _, state := range states {
		desc, ok := c.descriptor(state.histogram.Kind)
		if !ok {
			mlog().Warn("skipping unsupported Go runtime histogram", "kind", state.histogram.Kind)
			continue
		}

		data, err := state.histogram.Data()
		if err != nil {
			mlog().Warn("skipping malformed Go runtime histogram", "kind", state.histogram.Kind, "error", err)
			continue
		}
		if len(data.BucketCounts) != len(data.Bounds)+1 {
			mlog().Warn(
				"skipping malformed Go runtime histogram",
				"kind", state.histogram.Kind,
				"bucket_counts", len(data.BucketCounts),
				"bounds", len(data.Bounds),
			)
			continue
		}

		buckets := make(map[float64]uint64, len(data.Bounds))
		var cumulative uint64
		for i, upperBound := range data.Bounds {
			cumulative += data.BucketCounts[i]
			buckets[upperBound] = cumulative
		}
		metric, err := prometheus.NewConstHistogram(
			desc,
			data.Count,
			data.Sum,
			buckets,
			state.labels...,
		)
		if err != nil {
			mlog().Warn("skipping malformed Go runtime histogram", "kind", state.histogram.Kind, "error", err)
			continue
		}
		ch <- metric
	}
}

func (c *goRuntimeHistogramCollector) snapshot() []goRuntimeHistogramState {
	c.mu.RLock()
	snapshots := make(map[goRuntimeHistogramKey]goRuntimeHistogramState, len(c.histogramSnapshots))
	for key, state := range c.histogramSnapshots {
		snapshots[key] = clonePromRuntimeHistogramState(state)
	}
	retired := make(map[goRuntimeHistogramSeriesKey]goRuntimeHistogramState, len(c.retiredSnapshots))
	for key, state := range c.retiredSnapshots {
		retired[key] = clonePromRuntimeHistogramState(state)
	}
	c.mu.RUnlock()

	aggregated := retired
	invalid := make(map[goRuntimeHistogramSeriesKey]error)
	for key, state := range snapshots {
		seriesKey := goRuntimeHistogramSeriesKey{kind: key.kind, labelTuple: key.labelTuple}
		if _, skip := invalid[seriesKey]; skip {
			continue
		}
		current, exists := aggregated[seriesKey]
		if !exists {
			aggregated[seriesKey] = state
			continue
		}
		combined, err := aggregatePromRuntimeHistogramStates(current, state)
		if err != nil {
			delete(aggregated, seriesKey)
			invalid[seriesKey] = err
			continue
		}
		aggregated[seriesKey] = combined
	}
	for key, err := range invalid {
		mlog().Warn("skipping malformed Go runtime histogram", "kind", key.kind, "error", err)
	}

	states := make([]goRuntimeHistogramState, 0, len(aggregated))
	for _, state := range aggregated {
		states = append(states, state)
	}
	return states
}

func clonePromRuntimeHistogramState(state goRuntimeHistogramState) goRuntimeHistogramState {
	state.labels = append([]string(nil), state.labels...)
	state.histogram.Counts = append([]uint64(nil), state.histogram.Counts...)
	return state
}

func aggregatePromRuntimeHistogramStates(
	left goRuntimeHistogramState,
	right goRuntimeHistogramState,
) (goRuntimeHistogramState, error) {
	if len(left.histogram.Counts) != len(right.histogram.Counts) {
		return goRuntimeHistogramState{}, errors.New("population count mismatch")
	}

	var carry uint64
	left.histogram.Underflow, carry = bits.Add64(
		left.histogram.Underflow,
		right.histogram.Underflow,
		0,
	)
	if carry != 0 {
		return goRuntimeHistogramState{}, errors.New("population overflow")
	}
	left.histogram.Overflow, carry = bits.Add64(
		left.histogram.Overflow,
		right.histogram.Overflow,
		0,
	)
	if carry != 0 {
		return goRuntimeHistogramState{}, errors.New("population overflow")
	}
	for i, population := range right.histogram.Counts {
		left.histogram.Counts[i], carry = bits.Add64(left.histogram.Counts[i], population, 0)
		if carry != 0 {
			return goRuntimeHistogramState{}, errors.New("population overflow")
		}
	}
	return left, nil
}

func (c *goRuntimeHistogramCollector) descriptor(
	kind runtimemetrics.GoHistogramKind,
) (*prometheus.Desc, bool) {
	switch kind {
	case runtimemetrics.GoHistogramKindGCPause:
		return c.gcPauseDesc, true
	case runtimemetrics.GoHistogramKindSchedLatency:
		return c.scheduleDesc, true
	default:
		return nil, false
	}
}

func runtimeMetricLabelTuple(labels []string) string {
	key := make([]byte, 0, len(labels)*8)
	for _, label := range labels {
		key = strconv.AppendInt(key, int64(len(label)), 10)
		key = append(key, ':')
		key = append(key, label...)
	}
	return string(key)
}
