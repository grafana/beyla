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
	"log/slog"
	"time"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

// Accounter accumulates flows metrics in memory and eventually evicts them via an evictor channel.
// The accounting process is usually done at kernel-space. This type reimplements it at userspace
// for the edge case where packets are submitted directly via ring-buffer because the kernel-side
// accounting map is full.
type Accounter struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      map[ebpf.NetFlowId]*ebpf.NetFlowMetrics
}

func alog() *slog.Logger {
	return slog.With("component", "flow/Accounter")
}

// NewAccounter creates a new Accounter.
// The cache has no limit and it's assumed that eviction is done by the caller.
func NewAccounter(maxEntries int, evictTimeout time.Duration) *Accounter {
	return &Accounter{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      map[ebpf.NetFlowId]*ebpf.NetFlowMetrics{},
	}
}

// Account runs in a new goroutine. It reads all the records from the input channel
// and accumulate their metrics internally. Once the metrics have reached their max size
// or the eviction times out, it evicts all the accumulated flows by the returned channel.
func (c *Accounter) Account(in <-chan *ebpf.NetFlowRecordT, out chan<- []*ebpf.Record) {
	alog := alog()
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			evictingEntries := c.entries
			c.entries = map[ebpf.NetFlowId]*ebpf.NetFlowMetrics{}
			alog.Debug("evicting flows from userspace accounter on timeout", "flows", len(evictingEntries))
			c.evict(evictingEntries, out)
		case record, ok := <-in:
			if !ok {
				alog.Debug("input channel closed. Evicting entries")
				// if the records channel is closed, we evict the entries in the
				// same goroutine to wait for all the entries to be sent before
				// closing the channel
				c.evict(c.entries, out)
				alog.Debug("exiting account routine")
				return
			}
			if stored, ok := c.entries[record.Id]; ok {
				stored.Accumulate(&record.Metrics)
			} else {
				if len(c.entries) >= c.maxEntries {
					evictingEntries := c.entries
					c.entries = map[ebpf.NetFlowId]*ebpf.NetFlowMetrics{}
					alog.Debug("evicting flows from userspace accounter after reaching cache max length",
						"flows", len(evictingEntries))
					c.evict(evictingEntries, out)
				}
				c.entries[record.Id] = &record.Metrics
			}
		}
	}
}

func (c *Accounter) evict(entries map[ebpf.NetFlowId]*ebpf.NetFlowMetrics, evictor chan<- []*ebpf.Record) {
	records := make([]*ebpf.Record, 0, len(entries))
	for key, metrics := range entries {
		records = append(records, ebpf.NewRecord(key, *metrics))
	}
	alog().Debug("records evicted from userspace accounter", "numEntries", len(records))
	evictor <- records
}
