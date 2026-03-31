// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

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

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"

import (
	"context"
	"log/slog"
	"sync"
	"time"

	cebpf "github.com/cilium/ebpf"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
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
	evictionCond *sync.Cond
	imetrics     imetrics.Reporter
	log          *slog.Logger
}

type mapFetcher interface {
	LookupAndDeleteMap() map[ebpf.NetFlowId]*ebpf.NetFlowMetrics
	FlowPacketStatsMap() *cebpf.Map
}

func NewMapTracer(ctxInfo *global.ContextInfo, fetcher mapFetcher, evictionTimeout time.Duration) *MapTracer {
	return &MapTracer{
		imetrics:        ctxInfo.Metrics,
		mapFetcher:      fetcher,
		evictionTimeout: evictionTimeout,
		evictionCond:    sync.NewCond(&sync.Mutex{}),
		log:             mtlog(),
	}
}

// Flush forces reading (and removing) all the flows from the source eBPF map
// and sending the entries to the next stage in the pipeline
func (m *MapTracer) Flush() {
	m.evictionCond.Broadcast()
}

func (m *MapTracer) TraceLoop(out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		packetStats, err := NewPacketStats(m.mapFetcher.FlowPacketStatsMap())
		if err != nil {
			m.log.Warn("Can't setup metric: "+attr.VendorPrefix+"_network_dropped_flow_bytes", "err", err)
		}
		defer out.MarkCloseable()
		evictionTicker := time.NewTicker(m.evictionTimeout)
		go m.evictionSynchronization(ctx, out)
		for {
			select {
			case <-ctx.Done():
				evictionTicker.Stop()
				m.log.Debug("exiting trace loop due to context cancellation")
				return
			case <-evictionTicker.C:
				m.log.Debug("triggering flow eviction on timer")
				m.Flush()

				if count, err := packetStats.Count(); err != nil {
					m.log.Debug("Can't retrieve internal network packet stats", "err", err)
				} else {
					m.imetrics.BPFPacketStats(count.Total, count.Ignored)
				}
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
	for {
		// make sure we only evict once at a time, even if there are multiple eviction signals
		m.evictionCond.L.Lock()
		m.evictionCond.Wait()
		select {
		case <-ctx.Done():
			m.log.Debug("context canceled. Stopping goroutine before evicting flows")
			return
		default:
			m.log.Debug("evictionSynchronization signal received")
			m.evictFlows(ctx, out)
		}
		m.evictionCond.L.Unlock()
	}
}

func (m *MapTracer) evictFlows(ctx context.Context, forwardFlows *msg.Queue[[]*ebpf.Record]) {
	flowsMap := m.mapFetcher.LookupAndDeleteMap()
	forwardingFlows := make([]*ebpf.Record, 0, len(flowsMap))
	for flowKey, aggregatedMetrics := range flowsMap {
		forwardingFlows = append(forwardingFlows, ebpf.NewRecord(flowKey, *aggregatedMetrics))
	}
	select {
	case <-ctx.Done():
		m.log.Debug("skipping flow eviction as agent is being stopped")
	default:
		forwardFlows.SendCtx(ctx, forwardingFlows)
	}
	m.log.Debug("flows evicted", "len", len(forwardingFlows))
}
