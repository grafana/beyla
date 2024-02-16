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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

var oneIf1, oneIf2, twoIf1, twoIf2 *ebpf.Record

func init() {
	// oneIf1 and oneIf2 represent the same flow from 2 different interfaces
	oneIf1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 123, DstPort: 456, IfIndex: 1,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	oneIf1.Id.SrcMac, oneIf1.Id.DstMac = [6]uint8{0x1}, [6]uint8{0x1}

	oneIf2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 123, DstPort: 456, IfIndex: 2,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
	oneIf2.Id.SrcMac, oneIf2.Id.DstMac = [6]uint8{0x2}, [6]uint8{0x2}

	// twoIf1 and twoIf2 are another fow from 2 different interfaces and directions
	twoIf1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, Direction: 1, SrcPort: 333, DstPort: 456, IfIndex: 1,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	twoIf1.Id.SrcMac, twoIf1.Id.DstMac = [6]uint8{0x1}, [6]uint8{0x1}

	twoIf2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, Direction: 0, SrcPort: 333, DstPort: 456, IfIndex: 2,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
	twoIf2.Id.SrcMac, twoIf2.Id.DstMac = [6]uint8{0x2}, [6]uint8{0x2}

}

func TestDedupe(t *testing.T) {
	input := make(chan []*ebpf.Record, 100)
	output := make(chan []*ebpf.Record, 100)

	dedupe, err := DeduperProvider(Deduper{Type: DeduperFirstCome, ExpireTime: time.Minute, JustMark: false})
	require.NoError(t, err)
	go dedupe(input, output)

	input <- []*ebpf.Record{
		oneIf2, // record 1 at interface 2: should be accepted
		twoIf1, // record 2 at interface 1: should be accepted
		oneIf1, // record 1 duplicate at interface 1: should NOT be accepted
		oneIf1, //                                        (same record key, different interface)
		twoIf2, // record 2 duplicate at interface 2: should NOT be accepted
		oneIf2, // record 1 at interface 1: should be accepted (same record key, same interface)
	}
	deduped := receiveTimeout(t, output)
	assert.Equal(t, []*ebpf.Record{oneIf2, twoIf1, oneIf2}, deduped)

	// should still accept records with same key, same interface,
	// and discard these with same key, different interface
	input <- []*ebpf.Record{oneIf1, oneIf2}
	deduped = receiveTimeout(t, output)
	assert.Equal(t, []*ebpf.Record{oneIf2}, deduped)
}

func TestDedupe_JustMark(t *testing.T) {
	input := make(chan []*ebpf.Record, 100)
	output := make(chan []*ebpf.Record, 100)

	dedupe, err := DeduperProvider(Deduper{Type: DeduperFirstCome, ExpireTime: time.Minute, JustMark: true})
	require.NoError(t, err)
	go dedupe(input, output)

	input <- []*ebpf.Record{
		clone(oneIf2), // record 1 at interface 2: not duplicate
		clone(twoIf1), // record 2 at interface 1: not duplicate
		clone(oneIf1), // record 1 duplicate at interface 1: should be marked as duplicate
		clone(oneIf1), //                                        (same record key, different interface)
		clone(twoIf2), // record 2 duplicate at interface 2: should be marked as duplicate
		clone(oneIf2), // record 1 at interface 1: not duplicate (same record key, same interface)
	}
	deduped := receiveTimeout(t, output)

	assert.Equal(t, []*ebpf.Record{
		oneIf2,
		twoIf1,
		asDuplicate(oneIf1),
		asDuplicate(oneIf1),
		asDuplicate(twoIf2),
		oneIf2,
	}, deduped)

	// should still accept as non-duplicate records with same key, same interface,
	// and mark as duplicate these with same key, different interface
	input <- []*ebpf.Record{clone(oneIf1), clone(oneIf2)}
	deduped = receiveTimeout(t, output)
	assert.Equal(t, []*ebpf.Record{asDuplicate(oneIf1), oneIf2}, deduped)
}

func TestDedupe_EvictFlows(t *testing.T) {
	tm := &timerMock{now: time.Now()}
	timeNow = tm.Now
	input := make(chan []*ebpf.Record, 100)
	output := make(chan []*ebpf.Record, 100)

	dedupe, err := DeduperProvider(Deduper{Type: DeduperFirstCome, ExpireTime: 15 * time.Second, JustMark: false})
	require.NoError(t, err)
	go dedupe(input, output)

	// Should only accept records 1 and 2, at interface 1
	input <- []*ebpf.Record{oneIf1, twoIf1, oneIf2}
	assert.Equal(t, []*ebpf.Record{oneIf1, twoIf1},
		receiveTimeout(t, output))

	tm.Add(10 * time.Second)

	// After 10 seconds, it still filters existing flows from different interfaces
	input <- []*ebpf.Record{oneIf2}
	time.Sleep(100 * time.Millisecond)
	requireNoEviction(t, output)

	tm.Add(10 * time.Second)

	// Record 2 hasn't been accounted for >expiryTime, so it will accept the it again
	// whatever the interface.
	// Since record 1 was accessed 10 seconds ago (<expiry time) it will filter it
	input <- []*ebpf.Record{oneIf2, twoIf2, twoIf1}
	assert.Equal(t, []*ebpf.Record{twoIf2},
		receiveTimeout(t, output))

	tm.Add(20 * time.Second)

	// when all the records expire, the deduper is reset for that flow
	input <- []*ebpf.Record{oneIf2, twoIf2}
	assert.Equal(t, []*ebpf.Record{oneIf2, twoIf2},
		receiveTimeout(t, output))
}

type timerMock struct {
	// avoids data races in tests
	sync.RWMutex
	now time.Time
}

func (tm *timerMock) Add(duration time.Duration) {
	tm.Lock()
	defer tm.Unlock()
	tm.now = tm.now.Add(duration)
}

func (tm *timerMock) Now() time.Time {
	tm.RLock()
	defer tm.RUnlock()
	return tm.now
}

func clone(in *ebpf.Record) *ebpf.Record {
	out := *in
	return &out
}

func asDuplicate(in *ebpf.Record) *ebpf.Record {
	out := clone(in)
	out.Duplicate = true
	return out
}
