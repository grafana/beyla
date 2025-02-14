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
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
)

func TestPacketAggregation(t *testing.T) {
	type testCase struct {
		input    []ebpf.NetFlowMetrics
		expected ebpf.NetFlowMetrics
	}
	tcs := []testCase{{
		input: []ebpf.NetFlowMetrics{
			{Packets: 0, Bytes: 0, StartMonoTimeNs: 0, EndMonoTimeNs: 0, Flags: 1, IfaceDirection: 0},
			{Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1, IfaceDirection: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1, IfaceDirection: 0},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1, IfaceDirection: 0},
		},
		expected: ebpf.NetFlowMetrics{
			Packets: 0x7, Bytes: 0x22d, StartMonoTimeNs: 0x176a790b240b, EndMonoTimeNs: 0x176a792a755b, Flags: 1, IfaceDirection: 1,
		},
	}, {
		input: []ebpf.NetFlowMetrics{
			{Packets: 0x3, Bytes: 0x5c4, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1, IfaceDirection: 0},
			{Packets: 0x2, Bytes: 0x8c, StartMonoTimeNs: 0x17f3e9633a7f, EndMonoTimeNs: 0x17f3e96f164e, Flags: 1, IfaceDirection: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1, IfaceDirection: 1},
			{Packets: 0x0, Bytes: 0x0, StartMonoTimeNs: 0x0, EndMonoTimeNs: 0x0, Flags: 1, IfaceDirection: 1},
		},
		expected: ebpf.NetFlowMetrics{
			Packets: 0x5, Bytes: 0x5c4 + 0x8c, StartMonoTimeNs: 0x17f3e9613a7f, EndMonoTimeNs: 0x17f3e979816e, Flags: 1, IfaceDirection: 0,
		},
	}}
	ft := MapTracer{}
	for i, tc := range tcs {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			assert.Equal(t,
				tc.expected,
				ft.aggregate(tc.input))
		})
	}
}
