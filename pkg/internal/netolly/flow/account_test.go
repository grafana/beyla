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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const timeout = 5 * time.Second

var (
	srcAddr1 = [16]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x12, 0x34, 0x56, 0x78}
	srcAddr2 = [16]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0xaa, 0xbb, 0xcc, 0xdd}
	dstAddr1 = [16]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x43, 0x21, 0x00, 0xff}
	dstAddr2 = [16]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		0x11, 0x22, 0x33, 0x44}
)

var k1, k2, k3 ebpf.NetFlowId

func init() {
	k1 = ebpf.NetFlowId{SrcPort: 333, DstPort: 8080}
	k1.SrcIp.In6U.U6Addr8 = srcAddr1
	k1.DstIp.In6U.U6Addr8 = dstAddr1
	k2 = ebpf.NetFlowId{SrcPort: 12, DstPort: 8080}
	k2.SrcIp.In6U.U6Addr8 = srcAddr2
	k2.DstIp.In6U.U6Addr8 = dstAddr1
	k3 = ebpf.NetFlowId{SrcPort: 333, DstPort: 443}
	k3.SrcIp.In6U.U6Addr8 = srcAddr1
	k3.DstIp.In6U.U6Addr8 = dstAddr2
}

func TestEvict_MaxEntries(t *testing.T) {
	// GIVEN an accounter
	now := time.Date(2022, 8, 23, 16, 33, 22, 0, time.UTC)
	acc := NewAccounter(2, time.Hour, func() time.Time {
		return now
	}, func() time.Duration {
		return 1000
	})

	// WHEN it starts accounting new records
	inputs := make(chan *ebpf.NetFlowRecordT, 20)
	evictor := make(chan []*ebpf.Record, 20)

	go acc.Account(inputs, evictor)

	// THEN It does not evict anything until it surpasses the maximum size
	// or the eviction period is reached
	requireNoEviction(t, evictor)
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 123, Packets: 1, StartMonoTimeNs: 123, EndMonoTimeNs: 123, Flags: 1,
		},
	}
	inputs <- &ebpf.NetFlowRecordT{
		Id: k2,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 456, Packets: 1, StartMonoTimeNs: 456, EndMonoTimeNs: 456, Flags: 1,
		},
	}
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 321, Packets: 1, StartMonoTimeNs: 789, EndMonoTimeNs: 789, Flags: 1,
		},
	}
	requireNoEviction(t, evictor)

	// WHEN a new record surpasses the maximum number of records
	inputs <- &ebpf.NetFlowRecordT{
		Id: k3,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 111, Packets: 1, StartMonoTimeNs: 888, EndMonoTimeNs: 888, Flags: 1,
		},
	}

	// THEN the old records are evicted
	received := map[ebpf.NetFlowId]ebpf.Record{}
	r := receiveTimeout(t, evictor)
	require.Len(t, r, 2)
	received[r[0].Id] = *r[0]
	received[r[1].Id] = *r[1]

	requireNoEviction(t, evictor)

	// AND the returned records summarize the number of bytes and packages
	// of each flow
	assert.Equal(t, map[ebpf.NetFlowId]ebpf.Record{
		k1: {
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: k1,
				Metrics: ebpf.NetFlowMetrics{
					Bytes: 444, Packets: 2, StartMonoTimeNs: 123, EndMonoTimeNs: 789, Flags: 1,
				},
			},
			TimeFlowStart: now.Add(-(1000 - 123) * time.Nanosecond),
			TimeFlowEnd:   now.Add(-(1000 - 789) * time.Nanosecond),
		},
		k2: {
			NetFlowRecordT: ebpf.NetFlowRecordT{
				Id: k2,
				Metrics: ebpf.NetFlowMetrics{
					Bytes: 456, Packets: 1, StartMonoTimeNs: 456, EndMonoTimeNs: 456, Flags: 1,
				},
			},
			TimeFlowStart: now.Add(-(1000 - 456) * time.Nanosecond),
			TimeFlowEnd:   now.Add(-(1000 - 456) * time.Nanosecond),
		},
	}, received)
}

func TestEvict_Period(t *testing.T) {
	// GIVEN an accounter
	now := time.Date(2022, 8, 23, 16, 33, 22, 0, time.UTC)
	acc := NewAccounter(200, 20*time.Millisecond, func() time.Time {
		return now
	}, func() time.Duration {
		return 1000
	})

	// WHEN it starts accounting new records
	inputs := make(chan *ebpf.NetFlowRecordT, 20)
	evictor := make(chan []*ebpf.Record, 20)
	go acc.Account(inputs, evictor)

	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeNs: 123, EndMonoTimeNs: 123, Flags: 1,
		},
	}
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeNs: 456, EndMonoTimeNs: 456, Flags: 1,
		},
	}
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeNs: 789, EndMonoTimeNs: 789, Flags: 1,
		},
	}
	// Forcing at least one eviction here
	time.Sleep(30 * time.Millisecond)
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeNs: 1123, EndMonoTimeNs: 1123, Flags: 1,
		},
	}
	inputs <- &ebpf.NetFlowRecordT{
		Id: k1,
		Metrics: ebpf.NetFlowMetrics{
			Bytes: 10, Packets: 1, StartMonoTimeNs: 1456, EndMonoTimeNs: 1456, Flags: 1,
		},
	}

	// THEN it evicts them periodically if the size of the accounter
	// has not reached the maximum size
	records := receiveTimeout(t, evictor)
	require.Len(t, records, 1)
	assert.Equal(t, ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: k1,
			Metrics: ebpf.NetFlowMetrics{
				Bytes:           30,
				Packets:         3,
				StartMonoTimeNs: 123,
				EndMonoTimeNs:   789,
				Flags:           1,
			},
		},
		TimeFlowStart: now.Add(-1000 + 123),
		TimeFlowEnd:   now.Add(-1000 + 789),
	}, *records[0])
	records = receiveTimeout(t, evictor)
	require.Len(t, records, 1)
	assert.Equal(t, ebpf.Record{
		NetFlowRecordT: ebpf.NetFlowRecordT{
			Id: k1,
			Metrics: ebpf.NetFlowMetrics{
				Bytes:           20,
				Packets:         2,
				StartMonoTimeNs: 1123,
				EndMonoTimeNs:   1456,
				Flags:           1,
			},
		},
		TimeFlowStart: now.Add(-1000 + 1123),
		TimeFlowEnd:   now.Add(-1000 + 1456),
	}, *records[0])

	// no more flows are evicted
	time.Sleep(30 * time.Millisecond)
	requireNoEviction(t, evictor)
}

func receiveTimeout(t *testing.T, evictor <-chan []*ebpf.Record) []*ebpf.Record {
	t.Helper()
	select {
	case r := <-evictor:
		return r
	case <-time.After(timeout):
		require.Fail(t, "timeout while waiting for evicted record")
	}
	return nil
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
