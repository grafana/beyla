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

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

var oneIf1, oneIf2, twoIf1, twoIf2 *ebpf.Record

func init() {
	// oneIf1 and oneIf2 represent the same flow from 2 different interfaces
	oneIf1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, SrcPort: 123, DstPort: 456, IfIndex: 1,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1, IfaceDirection: 1,
	}}, Attrs: ebpf.RecordAttrs{Interface: "eth0"}}

	oneIf2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, SrcPort: 123, DstPort: 456, IfIndex: 2,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1, IfaceDirection: 1,
	}}, Attrs: ebpf.RecordAttrs{Interface: "123456789"}}

	// twoIf1 and twoIf2 are another flow from 2 different interfaces
	twoIf1 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, SrcPort: 333, DstPort: 456, IfIndex: 1,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1, IfaceDirection: 0,
	}}, Attrs: ebpf.RecordAttrs{Interface: "eth0"}}

	twoIf2 = &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{Id: ebpf.NetFlowId{
		EthProtocol: 1, SrcPort: 333, DstPort: 456, IfIndex: 2,
	}, Metrics: ebpf.NetFlowMetrics{
		Packets: 2, Bytes: 456, Flags: 1, IfaceDirection: 0,
	}}, Attrs: ebpf.RecordAttrs{Interface: "123456789"}}
}

func TestDedupe(t *testing.T) {
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	outputQueue := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQueue.Subscribe()
	dedupe, err := DeduperProvider(&Deduper{Type: DeduperFirstCome, FCTTL: time.Minute}, input, outputQueue)(t.Context())
	require.NoError(t, err)
	go dedupe(t.Context())

	input.Send([]*ebpf.Record{
		clone(oneIf2), // record 1 at interface 2: should be accepted
		clone(twoIf1), // record 2 at interface 1: should be accepted
		clone(oneIf1), // record 1 duplicate at interface 1: should NOT be accepted
		clone(oneIf1), //                                        (same record key, different interface)
		clone(twoIf2), // record 2 duplicate at interface 2: should NOT be accepted
		clone(oneIf2), // record 1 at interface 1: should be accepted (same record key, same interface)
	})
	deduped := testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{unset(oneIf2), unset(twoIf1), unset(oneIf2)}, deduped)

	// should still accept records with same key, same interface,
	// and discard these with same key, different interface
	input.Send([]*ebpf.Record{clone(oneIf1), clone(oneIf2)})
	deduped = testutil.ReadChannel(t, output, timeout)
	assert.Equal(t, []*ebpf.Record{unset(oneIf2)}, deduped)
}

func TestDedupe_EvictFlows(t *testing.T) {
	tm := &timerMock{now: time.Now()}
	timeNow = tm.Now
	input := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	outputQu := msg.NewQueue[[]*ebpf.Record](msg.ChannelBufferLen(100))
	output := outputQu.Subscribe()

	dedupe, err := DeduperProvider(&Deduper{Type: DeduperFirstCome, FCTTL: 15 * time.Second}, input, outputQu)(t.Context())
	require.NoError(t, err)
	go dedupe(t.Context())

	// Should only accept records 1 and 2, at interface 1
	input.Send([]*ebpf.Record{oneIf1, twoIf1, oneIf2})
	assert.Equal(t, []*ebpf.Record{oneIf1, twoIf1},
		testutil.ReadChannel(t, output, timeout))

	tm.Add(10 * time.Second)

	// After 10 seconds, it still filters existing flows from different interfaces
	input.Send([]*ebpf.Record{oneIf2})
	time.Sleep(100 * time.Millisecond)
	requireNoEviction(t, output)

	tm.Add(10 * time.Second)

	// Record 2 hasn't been accounted for >expiryTime, so it will accept the it again
	// whatever the interface.
	// Since record 1 was accessed 10 seconds ago (<expiry time) it will filter it
	input.Send([]*ebpf.Record{oneIf2, twoIf2, twoIf1})
	assert.Equal(t, []*ebpf.Record{twoIf2},
		testutil.ReadChannel(t, output, timeout))

	tm.Add(20 * time.Second)

	// when all the records expire, the deduper is reset for that flow
	input.Send([]*ebpf.Record{oneIf2, twoIf2})
	assert.Equal(t, []*ebpf.Record{oneIf2, twoIf2},
		testutil.ReadChannel(t, output, timeout))
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

func unset(in *ebpf.Record) *ebpf.Record {
	out := clone(in)
	out.Id.IfIndex = ebpf.InterfaceUnset
	return out
}

func requireNoEviction(t *testing.T, evictor <-chan []*ebpf.Record) {
	t.Helper()
	select {
	case r := <-evictor:
		require.Failf(t, "unexpected evicted record", "%+v", r)
	default:
		// ok!
	}
}
