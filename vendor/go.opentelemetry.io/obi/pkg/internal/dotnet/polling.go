// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"fmt"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func observePollingCounter(snapshot *runtimemetrics.DotnetRuntimeMetricSnapshot, counter runtimeCounter) error {
	const bytesPerMegabyte = 1_000_000
	var destination **int64
	value := counter.Value
	switch counter.Name {
	case "working-set":
		destination = &snapshot.ProcessMemoryWorkingSet
		value *= bytesPerMegabyte
	case "gc-committed":
		destination = &snapshot.GCCommittedMemory
		value *= bytesPerMegabyte
	case "threadpool-thread-count":
		destination = &snapshot.ThreadPoolThreadCount
	case "threadpool-queue-length":
		destination = &snapshot.ThreadPoolQueueLength
	case "active-timer-count":
		destination = &snapshot.TimerCount
	case "assembly-count":
		destination = &snapshot.AssemblyCount
	default:
		return nil
	}
	if counter.Increment || math.IsNaN(value) || value < 0 || value >= float64(math.MaxInt64) {
		return fmt.Errorf("invalid polling counter %q value: %v", counter.Name, counter.Value)
	}
	if counter.Name != "working-set" && counter.Name != "gc-committed" && math.Trunc(value) != value {
		return fmt.Errorf("fractional polling counter %q value: %v", counter.Name, counter.Value)
	}
	current := int64(value)
	*destination = &current
	return nil
}
