// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"
	"maps"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type runtimeCollection struct {
	gc            gcRound
	fragmentation gcFragmentation
	cumulative    cumulativeCounters
	polling       runtimemetrics.DotnetRuntimeMetricSnapshot
	// ProcessorCount is emitted when the session is enabled, not every interval.
	processorCount *int64
	// Type labels survive reconnects; counts belong to this session.
	exceptionTypes        *exceptionTypes
	exceptions            map[string]uint64
	exceptionsUnavailable bool
}

func (c *runtimeCollection) observeEvent(event netTraceRuntimeEvent) (*runtimemetrics.DotnetRuntimeMetricSnapshot, error) {
	if event.gc != nil {
		return nil, c.fragmentation.observe(*event.gc)
	}
	if event.exceptionsUnavailable {
		c.exceptions = nil
		c.exceptionsUnavailable = true
		return nil, nil
	}
	if event.exceptionWarning != "" {
		return nil, nil
	}
	if event.exceptionType != "" {
		if c.exceptionsUnavailable {
			return nil, nil
		}
		return nil, c.observeException(event.exceptionType, event.exceptionCount)
	}
	return c.observe(event.counter)
}

func (c *runtimeCollection) observeException(rawName string, count uint64) error {
	label, err := c.exceptionTypes.labelFor(rawName)
	if err != nil {
		return err
	}
	if count > math.MaxInt64-c.exceptions[label] {
		return fmt.Errorf("cumulative exception count overflow for %q", label)
	}
	if c.exceptions == nil {
		c.exceptions = make(map[string]uint64)
	}
	c.exceptions[label] += count
	return nil
}

func (c *runtimeCollection) observe(counter runtimeCounter) (*runtimemetrics.DotnetRuntimeMetricSnapshot, error) {
	if counter.Name == "processor-count" {
		count := int64(counter.Value)
		c.processorCount = &count
		return nil, nil
	}
	// System.Runtime polls working-set before the other supported counters.
	if c.polling.ProcessMemoryWorkingSet == nil && counter.Name != "working-set" {
		return nil, nil
	}
	var completed *runtimemetrics.DotnetRuntimeMetricSnapshot
	if counter.Name == "working-set" && c.polling.ProcessMemoryWorkingSet != nil {
		if c.polling.GCCollections[0] != nil {
			snapshot := c.polling
			snapshot.ProcessCPUCount = c.processorCount
			snapshot.Exceptions = maps.Clone(c.exceptions)
			snapshot.GCHeapFragmentation = c.fragmentation.snapshot()
			completed = &snapshot
		}
		c.polling = runtimemetrics.DotnetRuntimeMetricSnapshot{}
	}
	if err := observePollingCounter(&c.polling, counter); err != nil {
		return nil, err
	}
	if err := c.cumulative.observe(&c.polling, counter); err != nil {
		return nil, err
	}
	gcSnapshot, err := c.gc.observe(counter)
	if err != nil {
		return nil, err
	}
	if gcSnapshot != nil {
		c.polling.GCCollections = gcSnapshot.GCCollections
	}
	return completed, nil
}

func (c *runtimeCollection) finish() *runtimemetrics.DotnetRuntimeMetricSnapshot {
	// time-in-jit is the last supported counter in the runtime's polling order.
	if c.polling.JITCompilationTime == nil || c.polling.GCCollections[0] == nil {
		return nil
	}
	snapshot := c.polling
	snapshot.ProcessCPUCount = c.processorCount
	snapshot.Exceptions = maps.Clone(c.exceptions)
	snapshot.GCHeapFragmentation = c.fragmentation.snapshot()
	c.polling = runtimemetrics.DotnetRuntimeMetricSnapshot{}
	return &snapshot
}
