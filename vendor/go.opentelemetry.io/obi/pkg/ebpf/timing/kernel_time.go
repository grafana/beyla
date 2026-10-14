// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package timing // import "go.opentelemetry.io/obi/pkg/ebpf/timing"

import (
	"time"
)

// KernelTime converts a bpf_ktime_get_ns timestamp (CLOCK_MONOTONIC
// nanoseconds since boot) into wall-clock time, anchoring it against the
// current readings of both clocks.
func KernelTime(ktime uint64) time.Time {
	now := time.Now()
	delta := MonoTimeNow() - time.Duration(int64(ktime))
	return now.Add(-delta)
}
