// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

// AddSignedOffset applies a signed offset without wrapping the address space.
// Positive offsets move forward and negative offsets move backward from address.
// It returns false if the result would fall outside the uint64 address range.
func AddSignedOffset(address uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		positive := uint64(offset)
		if positive > ^uint64(0)-address {
			return 0, false
		}
		return address + positive, true
	}

	// Convert the negative offset without negating MinInt64, which would overflow.
	magnitude := uint64(-(offset + 1)) + 1
	if magnitude > address {
		return 0, false
	}
	return address - magnitude, true
}
