// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import "golang.org/x/sys/unix"

func currentTime() uint64 {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}

	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}
