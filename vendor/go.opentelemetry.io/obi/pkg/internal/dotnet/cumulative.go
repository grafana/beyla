// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type cumulativeInteger struct {
	total       uint64
	initialized bool
}

func (c *cumulativeInteger) observe(counter runtimeCounter) (uint64, error) {
	if !counter.Increment || math.IsNaN(counter.Value) || counter.Value < 0 ||
		counter.Value >= float64(math.MaxInt64) || math.Trunc(counter.Value) != counter.Value {
		return 0, fmt.Errorf("invalid cumulative increment for %q: %v", counter.Name, counter.Value)
	}
	if !c.initialized {
		c.initialized = true
		return 0, nil
	}
	increment := uint64(counter.Value)
	if increment > math.MaxInt64-c.total {
		return 0, fmt.Errorf("cumulative total overflow for %q", counter.Name)
	}
	c.total += increment
	return c.total, nil
}

type cumulativeDuration struct {
	seconds     float64
	initialized bool
}

func (c *cumulativeDuration) observe(counter runtimeCounter) (float64, error) {
	if !counter.Increment || math.IsNaN(counter.Value) || math.IsInf(counter.Value, 0) || counter.Value < 0 {
		return 0, fmt.Errorf("invalid duration increment for %q: %v", counter.Name, counter.Value)
	}
	if !c.initialized {
		c.initialized = true
		return 0, nil
	}
	const millisecondsPerSecond = 1_000
	seconds := c.seconds + counter.Value/millisecondsPerSecond
	if math.IsInf(seconds, 0) {
		return 0, fmt.Errorf("cumulative duration overflow for %q", counter.Name)
	}
	c.seconds = seconds
	return c.seconds, nil
}

type cumulativeCounters struct {
	allocated   cumulativeInteger
	pause       cumulativeDuration
	jitTime     cumulativeDuration
	workItems   cumulativeInteger
	contentions cumulativeInteger
}

func (c *cumulativeCounters) observe(snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot, counter runtimeCounter) error {
	var source *cumulativeInteger
	var destination **uint64
	var duration *cumulativeDuration
	var seconds **float64
	switch counter.Name {
	case "alloc-rate":
		source, destination = &c.allocated, &snapshot.GCHeapTotalAllocated
	case "threadpool-completed-items-count":
		source, destination = &c.workItems, &snapshot.ThreadPoolWorkItemCount
	case "monitor-lock-contention-count":
		source, destination = &c.contentions, &snapshot.MonitorLockContentions
	case "total-pause-time-by-gc":
		duration, seconds = &c.pause, &snapshot.GCPauseTime
	case "time-in-jit":
		duration, seconds = &c.jitTime, &snapshot.JITCompilationTime
	case "il-bytes-jitted":
		destination = &snapshot.JITCompiledILSize
	case "methods-jitted-count":
		destination = &snapshot.JITCompiledMethods
	default:
		return nil
	}
	if duration != nil {
		total, err := duration.observe(counter)
		if err != nil {
			return err
		}
		*seconds = &total
		return nil
	}
	if source == nil {
		// Absolute JIT totals include work from before attachment.
		if counter.Increment || math.IsNaN(counter.Value) || counter.Value < 0 ||
			counter.Value >= float64(math.MaxInt64) || math.Trunc(counter.Value) != counter.Value {
			return fmt.Errorf("invalid cumulative value for %q: %v", counter.Name, counter.Value)
		}
		total := uint64(counter.Value)
		*destination = &total
		return nil
	}
	total, err := source.observe(counter)
	if err != nil {
		return err
	}
	*destination = &total
	return nil
}
