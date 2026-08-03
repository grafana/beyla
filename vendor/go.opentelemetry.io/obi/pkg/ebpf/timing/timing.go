// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package timing // import "go.opentelemetry.io/obi/pkg/ebpf/timing"

import (
	"time"

	"golang.org/x/sys/unix"
)

// MonoTimeNow returns CLOCK_MONOTONIC nanoseconds, the same clock the
// ktime_get_ns() BPF helper reads, so BPF timestamps can be compared against
// it (e.g. to expire map entries) or converted with KernelTime. Go's
// runtime.nanotime() is not exposed as API, hence the syscall.
//
// darwin supports clock_gettime(CLOCK_MONOTONIC) too, so this is
// platform-independent: OBI only runs on Linux, but the package (and its
// tests) must behave on macOS development machines as well.
func MonoTimeNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}
