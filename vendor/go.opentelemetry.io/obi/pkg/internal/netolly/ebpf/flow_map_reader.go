// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"log/slog"
)

// flowMapLegacyReader reads, aggregates and removes all the flows in the eBPF flows map.
// This is a legacy implementation for RHEL8 and derivative distributions, which ship a
// custom 4.18 kernel that backports many eBPF features but don't ship BPF batch maps.
// https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/8.10_release_notes/available_bpf_features
// This implementation can be removed when we stop supporting RHEL8 and derived..
type flowMapLegacyReader[IT mapIterator] struct {
	log          *slog.Logger
	flowMap      ebpfMap[IT]
	cacheMaxSize int
	lastReadNS   uint64
}

type ebpfMap[IT mapIterator] interface {
	Delete(key any) error
	Iterate() IT
}

type mapIterator interface {
	Next(key any, value any) bool
}

// lookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key is the network flow identifier (e.g. src/dst addresses)
// and the value are the aggregated time and metrics for all the packets of this flow.
// For synchronization purposes, we get/delete a whole snapshot of the flows map.
// This way we avoid missing packets that could be updated on the
// ebpf side while we process/aggregate them here
// Changing this method invocation by BatchLookupAndDelete could improve performance
// Race conditions here causes that some flows might be lost in high-load scenarios
func (fmd *flowMapLegacyReader[IT]) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	flows := make(map[NetFlowId]*NetFlowMetrics, fmd.cacheMaxSize)
	oldestFlow := uint64(0)

	id := NetFlowId{}
	var metrics []NetFlowMetrics
	for iterator := fmd.flowMap.Iterate(); iterator.Next(&id, &metrics); {
		if err := fmd.flowMap.Delete(id); err != nil {
			fmd.log.Debug("couldn't delete flow entry", "flowId", id, "error", err)
		}

		perCPUAggregated := &NetFlowMetrics{}
		for i := range metrics {
			mt := &metrics[i]
			// eBPF hashmap values are not zeroed when the entry is removed. That causes that we
			// might receive entries from previous collect-eviction timeslots.
			// We need to check the flow time and discard old flows.
			if mt.StartMonoTimeNs <= fmd.lastReadNS || mt.EndMonoTimeNs <= fmd.lastReadNS {
				continue
			}
			perCPUAggregated.Accumulate(mt)
			oldestFlow = max(oldestFlow, mt.EndMonoTimeNs)
		}
		if perCPUAggregated.EndMonoTimeNs == 0 {
			// no recent flows were accounted, skip
			continue
		}

		// We observed that eBFP PerCPU map might insert multiple times the same key in the map
		// (probably due to race conditions) so we need to re-join metrics again at userspace
		if stored, ok := flows[id]; ok {
			stored.Accumulate(perCPUAggregated)
		} else {
			flows[id] = perCPUAggregated
		}
		metrics = nil
	}
	if oldestFlow != 0 {
		fmd.lastReadNS = oldestFlow
	}
	return flows, nil
}
