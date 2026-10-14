// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

// nodejsResetToleranceNs distinguishes a real counter reset from float64
// rounding: eventLoopUtilization() derives active as hrtime − loopStart − idle,
// so consecutive readings can regress by sub-µs rounding error. 1ms is ample
// headroom, and far below a real reset, which drops the whole accumulated value.
const nodejsResetToleranceNs = 1_000_000

// NodejsCounterDelta counts the full current value on the first sample and on
// counter resets (a restarted loop reports smaller cumulative values). Within-
// tolerance regressions clamp to zero — treating them as resets would re-add
// the entire cumulative history.
func NodejsCounterDelta(initialized bool, previous, current uint64) uint64 {
	if !initialized || current+nodejsResetToleranceNs < previous {
		return current
	}
	if current < previous {
		return 0
	}
	return current - previous
}
