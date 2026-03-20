// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import (
	"errors"

	"github.com/cilium/ebpf"
)

// TODO: make configurable
const defaultReadBatchLen = 1024

// flowMapBatchReader reads, aggregates and removes all the flows in the eBPF flows map
type flowMapBatchReader struct {
	flowMap      ebpfBatchMap
	lastReadNS   uint64
	cacheMaxSize int

	possibleCPUs int

	// given that lookupAndDeleteMap is not called concurrently, we can save some
	// allocations by reusing the lookup slice
	cachedKeys   []NetFlowId
	cachedValues []NetFlowMetrics
}

type ebpfBatchMap interface {
	BatchLookupAndDelete(cursor *ebpf.MapBatchCursor, keysOut, valuesOut any, opts *ebpf.BatchOptions) (int, error)
}

// lookupAndDeleteMap reads all the entries from the eBPF map and removes them from it.
// It returns a map where the key is the network flow identifier (e.g. src/dst addresses)
// and the value is the aggregated time and metrics for all the packets of this flow.
func (fmd *flowMapBatchReader) lookupAndDeleteMap() (map[NetFlowId]*NetFlowMetrics, error) {
	flows := make(map[NetFlowId]*NetFlowMetrics, fmd.cacheMaxSize)
	oldestFlow := uint64(0)
	cursor := ebpf.MapBatchCursor{}
	for {
		n, err := fmd.flowMap.BatchLookupAndDelete(&cursor, fmd.cachedKeys, fmd.cachedValues, nil)
		oldestFlow = max(oldestFlow, fmd.aggregateBatch(n, fmd.cachedKeys, fmd.cachedValues, flows))
		if err != nil {
			if oldestFlow != 0 {
				fmd.lastReadNS = oldestFlow
			}
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				// reaching the end of the map. We can stop reading
				return flows, nil
			}
			return flows, err
		}
	}
}

func (fmd *flowMapBatchReader) aggregateBatch(n int, keys []NetFlowId, values []NetFlowMetrics, flows map[NetFlowId]*NetFlowMetrics) uint64 {
	vi := 0
	oldestFlow := uint64(0)
	for ki := range n {
		perCPUAggregated := &NetFlowMetrics{}
		for range fmd.possibleCPUs {
			mt := &values[vi]
			vi++
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
		if stored, ok := flows[keys[ki]]; ok {
			stored.Accumulate(perCPUAggregated)
		} else {
			flows[keys[ki]] = perCPUAggregated
		}
	}
	return oldestFlow
}
