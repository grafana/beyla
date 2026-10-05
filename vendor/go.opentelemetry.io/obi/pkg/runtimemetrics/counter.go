// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

// CounterDelta returns the full value on initialization or reset, and the
// increase otherwise. Inputs must be finite, nonnegative cumulative values.
func CounterDelta[T int64 | uint64 | float64](previous *T, current T) T {
	if previous == nil || current < *previous {
		return current
	}
	return current - *previous
}
