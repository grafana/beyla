// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import "github.com/cilium/ebpf"

// RingbufWriteStats contains cumulative write counters from the eBPF map.
type RingbufWriteStats = BpfRingbufWriteStatsT

// LookupRingbufWriteStats reads and sums the per-CPU ring buffer write counters.
func LookupRingbufWriteStats(statsMap *ebpf.Map, key uint32) (RingbufWriteStats, error) {
	var perCPU []RingbufWriteStats
	if err := statsMap.Lookup(key, &perCPU); err != nil {
		return RingbufWriteStats{}, err
	}

	var total RingbufWriteStats
	for _, stats := range perCPU {
		total.Writes += stats.Writes
		total.Failures += stats.Failures
	}
	return total, nil
}
