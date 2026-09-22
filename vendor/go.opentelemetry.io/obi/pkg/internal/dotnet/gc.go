// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// uint64UpperBound is the first integer that cannot fit in a uint64.
const uint64UpperBound = 1 << 64

type gcCounts struct {
	collections [runtimemetrics.DotnetGCGenerationCount]uint64
	initialized [runtimemetrics.DotnetGCGenerationCount]bool
}

type gcRound struct {
	counts gcCounts
	seen   [runtimemetrics.DotnetGCGenerationCount]bool
	last   [runtimemetrics.DotnetGCGenerationCount]uint64
}

// observe publishes only complete rounds. Polling the three GC generation counters is not
// atomic, so an inconsistent or temporarily decreasing exclusive total waits
// for a later round to catch up.
func (g *gcRound) observe(counter runtimeCounter) (*runtimemetrics.DotnetRuntimeMetricSnapshot, error) {
	generation, ok := gcGeneration(counter.Name)
	if !ok {
		return nil, nil
	}
	if g.seen[generation] {
		return nil, fmt.Errorf("incomplete GC sampling round before %q", counter.Name)
	}
	if err := g.counts.observe(counter); err != nil {
		return nil, err
	}
	g.seen[generation] = true
	for _, seen := range g.seen {
		if !seen {
			return nil, nil
		}
	}
	g.seen = [runtimemetrics.DotnetGCGenerationCount]bool{}
	snapshot := g.counts.snapshot()
	for generation, count := range snapshot.GCCollections {
		if count == nil || *count < g.last[generation] {
			return nil, nil
		}
	}
	for generation, count := range snapshot.GCCollections {
		g.last[generation] = *count
	}
	return &snapshot, nil
}

// snapshot converts inclusive GC totals to exclusive generation counts and copies
// them for the pipeline. Callers must use a complete sampling round.
func (g *gcCounts) snapshot() runtimemetrics.DotnetRuntimeMetricSnapshot {
	var snapshot runtimemetrics.DotnetRuntimeMetricSnapshot
	for generation, initialized := range g.initialized {
		if !initialized {
			continue
		}
		count := g.collections[generation]
		if next := generation + 1; next < len(g.collections) {
			if !g.initialized[next] || count < g.collections[next] {
				continue
			}
			count -= g.collections[next]
		}
		snapshot.GCCollections[generation] = &count
	}
	return snapshot
}

// observe accumulates GC collections after each generation's first sample.
// The first increment can contain collections from before this session attached.
func (g *gcCounts) observe(counter runtimeCounter) error {
	generation, ok := gcGeneration(counter.Name)
	if !ok {
		return nil
	}
	if !counter.Increment || math.IsNaN(counter.Value) || counter.Value < 0 ||
		counter.Value >= uint64UpperBound || math.Trunc(counter.Value) != counter.Value {
		return fmt.Errorf("invalid GC collection increment for %q: %v", counter.Name, counter.Value)
	}
	if !g.initialized[generation] {
		g.initialized[generation] = true
		return nil
	}
	increment := uint64(counter.Value)
	if increment > math.MaxUint64-g.collections[generation] {
		return fmt.Errorf("GC collection total overflow for %q", counter.Name)
	}
	g.collections[generation] += increment
	return nil
}

func gcGeneration(name string) (int, bool) {
	switch name {
	case "gen-0-gc-count":
		return 0, true
	case "gen-1-gc-count":
		return 1, true
	case "gen-2-gc-count":
		return 2, true
	default:
		return 0, false
	}
}
