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
)

var (
	// the same flow from 2 different interfaces
	oneIf1 = &Record{RawRecord: RawRecord{RecordKey: RecordKey{
		EthProtocol: 1, Direction: 1, Transport: Transport{SrcPort: 123, DstPort: 456},
		DataLink: DataLink{DstMac: MacAddr{0x1}, SrcMac: MacAddr{0x1}}, IFIndex: 1,
	}, RecordMetrics: RecordMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	oneIf2 = &Record{RawRecord: RawRecord{RecordKey: RecordKey{
		EthProtocol: 1, Direction: 1, Transport: Transport{SrcPort: 123, DstPort: 456},
		DataLink: DataLink{DstMac: MacAddr{0x2}, SrcMac: MacAddr{0x2}}, IFIndex: 2,
	}, RecordMetrics: RecordMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
	// another fow from 2 different interfaces and directions
	twoIf1 = &Record{RawRecord: RawRecord{RecordKey: RecordKey{
		EthProtocol: 1, Direction: 1, Transport: Transport{SrcPort: 333, DstPort: 456},
		DataLink: DataLink{DstMac: MacAddr{0x1}, SrcMac: MacAddr{0x1}}, IFIndex: 1,
	}, RecordMetrics: RecordMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "eth0"}
	twoIf2 = &Record{RawRecord: RawRecord{RecordKey: RecordKey{
		EthProtocol: 1, Direction: 0, Transport: Transport{SrcPort: 333, DstPort: 456},
		DataLink: DataLink{DstMac: MacAddr{0x2}, SrcMac: MacAddr{0x2}}, IFIndex: 2,
	}, RecordMetrics: RecordMetrics{
		Packets: 2, Bytes: 456, Flags: 1,
	}}, Interface: "123456789"}
)

func TestDedupe(t *testing.T) {
	input := make(chan []*Record, 100)
	output := make(chan []*Record, 100)

	dedupe, err := DeduperProvider(Deduper{Type: DeduperFirstCome, ExpireTime: time.Minute, JustMark: false})
	require.NoError(t, err)
	go dedupe(input, output)

	input <- []*Record{
		oneIf2, // record 1 at interface 2: should be accepted
		twoIf1, // record 2 at interface 1: should be accepted
		oneIf1, // record 1 duplicate at interface 1: should NOT be accepted
		oneIf1, //                                        (same record key, different interface)
		twoIf2, // record 2 duplicate at interface 2: should NOT be accepted
		oneIf2, // record 1 at interface 1: should be accepted (same record key, same interface)
	}
	deduped := receiveTimeout(t, output)
	assert.Equal(t, []*Record{oneIf2, twoIf1, oneIf2}, deduped)

	// should still accept records with same key, same interface,
	// and discard these with same key, different interface
	input <- []*Record{oneIf1, oneIf2}
	deduped = receiveTimeout(t, output)
	assert.Equal(t, []*Record{oneIf2}, deduped)
}

func TestDedupe_EvictFlows(t *testing.T) {
	tm := &timerMock{now: time.Now()}
	timeNow = tm.Now
	input := make(chan []*Record, 100)
	output := make(chan []*Record, 100)

	dedupe, err := DeduperProvider(Deduper{Type: DeduperFirstCome, ExpireTime: 15 * time.Second, JustMark: false})
	require.NoError(t, err)
	go dedupe(input, output)

	// Should only accept records 1 and 2, at interface 1
	input <- []*Record{oneIf1, twoIf1, oneIf2}
	assert.Equal(t, []*Record{oneIf1, twoIf1},
		receiveTimeout(t, output))

	tm.Add(10 * time.Second)

	// After 10 seconds, it still filters existing flows from different interfaces
	input <- []*Record{oneIf2}
	time.Sleep(100 * time.Millisecond)
	requireNoEviction(t, output)

	tm.Add(10 * time.Second)

	// Record 2 hasn't been accounted for >expiryTime, so it will accept the it again
	// whatever the interface.
	// Since record 1 was accessed 10 seconds ago (<expiry time) it will filter it
	input <- []*Record{oneIf2, twoIf2, twoIf1}
	assert.Equal(t, []*Record{twoIf2},
		receiveTimeout(t, output))

	tm.Add(20 * time.Second)

	// when all the records expire, the deduper is reset for that flow
	input <- []*Record{oneIf2, twoIf2}
	assert.Equal(t, []*Record{oneIf2, twoIf2},
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
