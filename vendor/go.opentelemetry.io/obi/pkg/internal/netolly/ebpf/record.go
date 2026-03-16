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

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"encoding/binary"
	"io"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
)

// Record contains accumulated metrics from a flow, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions RecordGetters
// in pkg/internal/netolly/ebpf/record_getters.go and getDefinitions in
// pkg/export/attributes/attr_defs.go
type Record struct {
	NetFlowRecordT

	// Attrs of the flow record: source/destination, OBI IP, etc...
	CommonAttrs pipe.CommonAttrs

	NetAttrs NetAttrs
}

type NetAttrs struct {
	Interface string
}

func NewRecord(
	key NetFlowId,
	metrics NetFlowMetrics,
) *Record {
	return &Record{
		NetFlowRecordT: NetFlowRecordT{
			Id:      key,
			Metrics: metrics,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: pipe.IPAddr(key.SrcIp.In6U.U6Addr8),
			DstAddr: pipe.IPAddr(key.DstIp.In6U.U6Addr8),
		},
	}
}

func (fm *NetFlowMetrics) Accumulate(src *NetFlowMetrics) {
	// time == 0 if the value has not been yet set
	if fm.StartMonoTimeNs == 0 || fm.StartMonoTimeNs > src.StartMonoTimeNs {
		fm.StartMonoTimeNs = src.StartMonoTimeNs
		// set IfaceDirection here, because the correct value is in the first packet only
		fm.IfaceDirection = src.IfaceDirection
		fm.Initiator = src.Initiator
	}
	if fm.EndMonoTimeNs == 0 || fm.EndMonoTimeNs < src.EndMonoTimeNs {
		fm.EndMonoTimeNs = src.EndMonoTimeNs
	}
	fm.Bytes += src.Bytes
	fm.Packets += src.Packets
	fm.Flags |= src.Flags
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (NetFlowRecordT, error) {
	var fr NetFlowRecordT
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return fr, err
}
