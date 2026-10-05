// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"errors"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// cumulativeSessionTotals retains the last published attachment-relative values.
type cumulativeSessionTotals struct {
	allocated   uint64
	pause       float64
	jitTime     float64
	workItems   uint64
	contentions uint64
}

// merge applies the session's fixed baseline and retains the resulting totals.
func (t *cumulativeSessionTotals) merge(base cumulativeSessionTotals, snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot) error {
	next := *t
	for _, counter := range []struct {
		value *uint64
		base  uint64
		total *uint64
	}{
		{snapshot.GCHeapTotalAllocated, base.allocated, &next.allocated},
		{snapshot.ThreadPoolWorkItemCount, base.workItems, &next.workItems},
		{snapshot.MonitorLockContentions, base.contentions, &next.contentions},
	} {
		if counter.value == nil {
			continue
		}
		if *counter.value > math.MaxInt64-counter.base {
			return errors.New(".NET cumulative counter exceeds exporter integer range")
		}
		*counter.value += counter.base
		*counter.total = *counter.value
	}
	for _, counter := range []struct {
		value *float64
		base  float64
		total *float64
	}{
		{snapshot.GCPauseTime, base.pause, &next.pause},
		{snapshot.JITCompilationTime, base.jitTime, &next.jitTime},
	} {
		if counter.value == nil {
			continue
		}
		seconds := *counter.value + counter.base
		if math.IsInf(seconds, 0) {
			return errors.New(".NET cumulative duration overflow")
		}
		*counter.value = seconds
		*counter.total = seconds
	}
	*t = next
	return nil
}
