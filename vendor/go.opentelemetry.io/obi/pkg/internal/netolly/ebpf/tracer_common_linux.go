// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"errors"

	"github.com/cilium/ebpf"
)

var errFlowPacketStatsMapNotInitialized = errors.New("flow packet stats map not initialized")

// lookupPacketStats is a common function called by LookupPacketStats().
// Returns errFlowPacketStatsMapNotInitialized after Close().
func lookupPacketStats(m *ebpf.Map) (NetPacketCount, error) {
	if m == nil {
		return NetPacketCount{}, errFlowPacketStatsMapNotInitialized
	}
	var perCPUCounts []NetPacketCount
	if err := m.Lookup(uint32(0), &perCPUCounts); err != nil {
		return NetPacketCount{}, err
	}
	var sum NetPacketCount
	for _, pc := range perCPUCounts {
		sum.Total += pc.Total
		sum.Ignored += pc.Ignored
	}
	return sum, nil
}
