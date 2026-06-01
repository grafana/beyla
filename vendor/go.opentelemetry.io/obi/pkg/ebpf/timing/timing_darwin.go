// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package timing // import "go.opentelemetry.io/obi/pkg/ebpf/timing"

import (
	"time"
)

// MonoTimeNow returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper, e.g. needed to check
// the timeout in sec for BPF entries. We return the raw nsec,
// although that is not quite usable for comparison. Go has
// runtime.nanotime() but doesn't expose it as API.
func MonoTimeNow() time.Duration {
	return time.Duration(time.Now().Nanosecond())
}
