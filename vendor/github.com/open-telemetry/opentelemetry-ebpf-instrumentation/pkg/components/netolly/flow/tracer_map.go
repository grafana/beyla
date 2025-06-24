// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package flow

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/gavv/monotime"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

func mtlog() *slog.Logger {
	return slog.With("component", "flow.MapTracer")
}

// MapTracer accesses a mapped source of flows (the eBPF PerCPU HashMap), deserializes it into
// a flow Record structure, and performs the accumulation of each perCPU-record into a single flow
type MapTracer struct {
	mapFetcher      mapFetcher
	evictionTimeout time.Duration
	// manages the access to the eviction routines, avoiding two evictions happening at the same time
	evictionCond   *sync.Cond
	lastEvictionNs uint64
}

type mapFetcher interface {
	LookupAndDeleteMap() map[ebpf.NetFlowId][]ebpf.NetFlowMetrics
}

func NewMapTracer(fetcher mapFetcher, evictionTimeout time.Duration) *MapTracer {
	return &MapTracer{
		mapFetcher:      fetcher,
		evictionTimeout: evictionTimeout,
		lastEvictionNs:  uint64(monotime.Now()),
		evictionCond:    sync.NewCond(&sync.Mutex{}),
	}
}

// Flush forces reading (and removing) all the flows from the source eBPF map
// and sending the entries to the next stage in the pipeline
func (m *MapTracer) Flush() {
	m.evictionCond.Broadcast()
}

func (m *MapTracer) TraceLoop(out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		evictionTicker := time.NewTicker(m.evictionTimeout)
		go m.evictionSynchronization(ctx, out)
		mtlog := mtlog()
		for {
			select {
			case <-ctx.Done():
				evictionTicker.Stop()
				mtlog.Debug("exiting trace loop due to context cancellation")
				return
			case <-evictionTicker.C:
				mtlog.Debug("triggering flow eviction on timer")
				m.Flush()
			}
		}
	}
}

// evictionSynchronization loop just waits for the evictionCond to happen
// and triggers the actual eviction. It makes sure that only one eviction
// is being triggered at the same time
func (m *MapTracer) evictionSynchronization(ctx context.Context, out *msg.Queue[[]*ebpf.Record]) {
	// flow eviction loop. It just keeps waiting for eviction until someone triggers the
	// evictionCond.Broadcast signal
	mtlog := mtlog()
	for {
		// make sure we only evict once at a time, even if there are multiple eviction signals
		m.evictionCond.L.Lock()
		m.evictionCond.Wait()
		select {
		case <-ctx.Done():
			mtlog.Debug("context canceled. Stopping goroutine before evicting flows")
			return
		default:
			mtlog.Debug("evictionSynchronization signal received")
			m.evictFlows(ctx, out)
		}
		m.evictionCond.L.Unlock()
	}
}

func (m *MapTracer) evictFlows(ctx context.Context, forwardFlows *msg.Queue[[]*ebpf.Record]) {
	var forwardingFlows []*ebpf.Record
	laterFlowNs := uint64(0)
	for flowKey, flowMetrics := range m.mapFetcher.LookupAndDeleteMap() {
		aggregatedMetrics := m.aggregate(flowMetrics)
		// we ignore metrics that haven't been aggregated (e.g. all the mapped values are ignored)
		if aggregatedMetrics.EndMonoTimeNs == 0 {
			continue
		}
		// If it iterated an entry that do not have updated flows
		if aggregatedMetrics.EndMonoTimeNs > laterFlowNs {
			laterFlowNs = aggregatedMetrics.EndMonoTimeNs
		}
		forwardingFlows = append(forwardingFlows, ebpf.NewRecord(flowKey, aggregatedMetrics))
	}
	m.lastEvictionNs = laterFlowNs
	mtlog := mtlog()
	select {
	case <-ctx.Done():
		mtlog.Debug("skipping flow eviction as agent is being stopped")
	default:
		forwardFlows.Send(forwardingFlows)
	}
	mtlog.Debug("flows evicted", "len", len(forwardingFlows))
}

func (m *MapTracer) aggregate(metrics []ebpf.NetFlowMetrics) ebpf.NetFlowMetrics {
	if len(metrics) == 0 {
		mtlog().Warn("invoked aggregate with no values")
		return ebpf.NetFlowMetrics{}
	}
	aggr := ebpf.NetFlowMetrics{}
	for _, mt := range metrics {
		// eBPF hashmap values are not zeroed when the entry is removed. That causes that we
		// might receive entries from previous collect-eviction timeslots.
		// We need to check the flow time and discard old flows.
		if mt.StartMonoTimeNs <= m.lastEvictionNs || mt.EndMonoTimeNs <= m.lastEvictionNs {
			continue
		}
		aggr.Accumulate(&mt)
	}
	return aggr
}
