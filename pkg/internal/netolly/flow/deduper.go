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
	"container/list"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

func dlog() *slog.Logger {
	return slog.With("component", "flow/Deduper")
}

const (
	DeduperNone      = "none"
	DeduperFirstCome = "first_come"
)

type Deduper struct {
	Type       string
	ExpireTime time.Duration
}

func (d Deduper) Enabled() bool {
	return d.Type == DeduperFirstCome
}

var timeNow = time.Now

// deduperCache implement a LRU cache whose elements are evicted if they haven't been accessed
// during the expire duration.
// It is not safe for concurrent access.
type deduperCache struct {
	expire time.Duration
	// key: ebpf.NetFlowId with the interface and MACs erased, to detect duplicates
	// value: listElement pointing to a struct entry
	ifaces map[ebpf.NetFlowId]*list.Element
	// element: entry structs of the ifaces map ordered by expiry time
	entries *list.List
}

type entry struct {
	key        *ebpf.NetFlowId
	ifIndex    uint32
	expiryTime time.Time
}

// DeduperProvider receives flows and filters these belonging to duplicate interfaces. It will forward
// the flows from the first interface coming to it, until that flow expires in the cache
// (no activity for it during the expiration time)
// After passing by the deduper, the ebpf.Record instances loose their IfIndex and Direction fields.
func DeduperProvider(dd *Deduper) (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	if !dd.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just bypassing it.
		return pipe.Bypass[[]*ebpf.Record](), nil
	}
	cache := &deduperCache{
		expire:  dd.ExpireTime,
		entries: list.New(),
		ifaces:  map[ebpf.NetFlowId]*list.Element{},
	}
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		for records := range in {
			cache.removeExpired()
			fwd := make([]*ebpf.Record, 0, len(records))
			for _, record := range records {
				if cache.isDupe(&record.Id) {
					continue
				}
				// Before forwarding, unset the non-common fields of deduplicate flows.
				// These values are not relevant after deduplication and keeping them
				// would unnecessarily increase cardinality, as they could chaotically
				// contain the different interfaces.
				record.Id.IfIndex = ebpf.InterfaceUnset

				fwd = append(fwd, record)
			}
			if len(fwd) > 0 {
				out <- fwd
			}
		}
	}, nil
}

// isDupe returns whether the passed record has been already checked for duplicate for
// another interface
func (c *deduperCache) isDupe(key *ebpf.NetFlowId) bool {
	rk := *key
	// zeroes fields from key that should be ignored from the flow comparison
	rk.IfIndex = 0
	// If a flow has been accounted previously, whatever its interface was,
	// it updates the expiry time for that flow
	if ele, ok := c.ifaces[rk]; ok {
		fEntry := ele.Value.(*entry)
		fEntry.expiryTime = timeNow().Add(c.expire)
		c.entries.MoveToFront(ele)
		// The input flow is duplicate if its interface is different to the interface
		// of the non-duplicate flow that was first registered in the cache
		return fEntry.ifIndex != key.IfIndex
	}
	// The flow has not been accounted previously (or was forgotten after expiration)
	// so we register it for that concrete interface
	e := entry{
		key:        &rk,
		ifIndex:    key.IfIndex,
		expiryTime: timeNow().Add(c.expire),
	}
	c.ifaces[rk] = c.entries.PushFront(&e)
	return false
}

func (c *deduperCache) removeExpired() {
	now := timeNow()
	ele := c.entries.Back()
	evicted := 0
	for ele != nil && now.After(ele.Value.(*entry).expiryTime) {
		evicted++
		c.entries.Remove(ele)
		delete(c.ifaces, *ele.Value.(*entry).key)
		ele = c.entries.Back()
	}
	if evicted > 0 {
		dlog().Debug("entries evicted from the deduper cache",
			"current", c.entries.Len(),
			"evicted", evicted,
			"expiryTime", c.expire)
	}
}
