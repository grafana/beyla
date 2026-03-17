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

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"

import (
	"github.com/cilium/ebpf"

	ebpf2 "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
)

// PacketStats provides access to the internal BPF accounting of how many
// flow packets are accounted in the namespace and how many are ignored in the
// BPF space due to internal map collisions
type PacketStats struct {
	bpfPacketStats *ebpf.Map
}

func NewPacketStats(bpfPacketStats *ebpf.Map) (PacketStats, error) {
	return PacketStats{
		bpfPacketStats: bpfPacketStats,
	}, nil
}

func (fm *PacketStats) Count() (ebpf2.NetPacketCount, error) {
	if fm.bpfPacketStats == nil {
		return ebpf2.NetPacketCount{}, nil
	}

	var perCPUCounts []ebpf2.NetPacketCount
	if err := fm.bpfPacketStats.Lookup(uint32(0), &perCPUCounts); err != nil {
		_ = fm.bpfPacketStats.Close()
		return ebpf2.NetPacketCount{}, err
	}

	var sum ebpf2.NetPacketCount
	for _, pc := range perCPUCounts {
		sum.Total += pc.Total
		sum.Ignored += pc.Ignored
	}

	return sum, nil
}
