// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
)

type bpfProbeKey struct {
	probeID   string
	probeType string
	probeName string
}

// bpfProbeLatencyState accumulates the cumulative distribution of a single probe.
// BpfProbeStats reports per-interval deltas for count and sum, while the bucket map it
// receives is already cumulative, so only the former are accumulated here.
type bpfProbeLatencyState struct {
	time    time.Time
	count   uint64
	sum     float64
	buckets map[float64]uint64
}

// subtractBpfProbeLatency returns the delta between two cumulative snapshots. A snapshot that
// went backwards, which happens when the kernel reuses a program ID, is treated as a fresh
// series rather than producing negative counts.
func subtractBpfProbeLatency(current, previous bpfProbeLatencyState) bpfProbeLatencyState {
	if current.count < previous.count || current.sum < previous.sum {
		return current
	}

	delta := bpfProbeLatencyState{
		count:   current.count - previous.count,
		sum:     current.sum - previous.sum,
		buckets: make(map[float64]uint64, len(current.buckets)),
	}
	for bound, count := range current.buckets {
		if previousCount := previous.buckets[bound]; count >= previousCount {
			delta.buckets[bound] = count - previousCount
		}
	}

	return delta
}

// bpfProbeLatencyProducer emits the eBPF probe latency distribution as a pre-aggregated
// histogram. An SDK Float64Histogram cannot express "add N observations to this bucket",
// which is the only form the kernel exposes, so this implements the SDK Producer interface
// instead and emits explicit bounds and bucket counts.
type bpfProbeLatencyProducer struct {
	mu           sync.Mutex
	name         attributes.Name
	temporality  metricdata.Temporality
	startTime    time.Time
	probes       map[bpfProbeKey]*bpfProbeLatencyState
	lastProduced map[bpfProbeKey]bpfProbeLatencyState
}

func newBpfProbeLatencyProducer(name attributes.Name, temporality metricdata.Temporality) *bpfProbeLatencyProducer {
	return &bpfProbeLatencyProducer{
		name:         name,
		temporality:  temporality,
		startTime:    timeNow(),
		probes:       make(map[bpfProbeKey]*bpfProbeLatencyState),
		lastProduced: make(map[bpfProbeKey]bpfProbeLatencyState),
	}
}

func (p *bpfProbeLatencyProducer) Update(
	probeID, probeType, probeName string,
	count uint64,
	latencySumSeconds float64,
	latencyBuckets map[float64]uint64,
) {
	// probe names come from eBPF program info; sanitizing on the way in keeps the
	// aggregation key and the exported attribute consistent.
	key := bpfProbeKey{
		probeID:   attributes.SanitizeUTF8(probeID),
		probeType: attributes.SanitizeUTF8(probeType),
		probeName: attributes.SanitizeUTF8(probeName),
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	state, ok := p.probes[key]
	if !ok {
		state = &bpfProbeLatencyState{}
		p.probes[key] = state
	}

	state.count += count
	state.sum += latencySumSeconds
	// the caller keeps mutating its map between intervals
	state.buckets = maps.Clone(latencyBuckets)
}

func (p *bpfProbeLatencyProducer) Produce(ctx context.Context) ([]metricdata.ScopeMetrics, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.probes) == 0 {
		return nil, nil
	}

	now := timeNow()
	delta := p.temporality == metricdata.DeltaTemporality
	dataPoints := make([]metricdata.HistogramDataPoint[float64], 0, len(p.probes))
	for key, state := range p.probes {
		emitted := *state
		startTime := p.startTime
		if delta {
			previous := p.lastProduced[key]
			emitted = subtractBpfProbeLatency(*state, previous)
			startTime = previous.time
			if startTime.IsZero() {
				startTime = p.startTime
			}
		}

		dataPoints = append(dataPoints, metricdata.HistogramDataPoint[float64]{
			Attributes: attribute.NewSet(
				attribute.String(string(attr.BpfProbeID), key.probeID),
				attribute.String(string(attr.BpfProbeType), key.probeType),
				attribute.String(string(attr.BpfProbeName), key.probeName),
			),
			StartTime:    startTime,
			Time:         now,
			Count:        emitted.count,
			Sum:          emitted.sum,
			Bounds:       slices.Clone(imetrics.BpfLatenciesBuckets),
			BucketCounts: bucketCounts(&emitted),
		})

		if delta {
			produced := *state
			produced.buckets = maps.Clone(state.buckets)
			produced.time = now
			p.lastProduced[key] = produced
		}
	}

	return []metricdata.ScopeMetrics{{
		Scope: instrumentation.Scope{Name: internalMetricsMeterName},
		Metrics: []metricdata.Metrics{{
			Name:        p.name.OTEL,
			Description: "Latency distribution of the eBPF probe in seconds",
			Unit:        p.name.Unit,
			Data: metricdata.Histogram[float64]{
				Temporality: metricdata.CumulativeTemporality,
				DataPoints:  dataPoints,
			},
		}},
	}}, nil
}

// bucketCounts converts the per-bound counts the kernel-side accounting produces into the
// BucketCounts layout the SDK expects: one entry per bound plus a trailing overflow bucket
// for observations above the largest bound, which the accounting does not record.
func bucketCounts(state *bpfProbeLatencyState) []uint64 {
	counts := make([]uint64, len(imetrics.BpfLatenciesBuckets)+1)

	var bounded uint64
	for i, bound := range imetrics.BpfLatenciesBuckets {
		counts[i] = state.buckets[bound]
		bounded += counts[i]
	}

	// The bucket map must hold per-bucket counts, not the cumulative "le" counts Prometheus
	// uses; otherwise the totals below would exceed the observation count and the datapoint
	// would be invalid. Fall back to attributing everything to the overflow bucket, which is
	// wrong but stays self-consistent.
	if bounded > state.count {
		clear(counts)
		counts[len(counts)-1] = state.count
		return counts
	}

	counts[len(counts)-1] = state.count - bounded

	return counts
}
