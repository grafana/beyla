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

package ebpf

import (
	"encoding/binary"
	"io"
	"net"

	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

// Record contains accumulated metrics from a flow, with extra metadata
// that is added from the user space
// REMINDER: any attribute here must be also added to the functions RecordGetters
// and getDefinitions in pkg/internal/export/metric/definitions.go
type Record struct {
	NetFlowRecordT

	// Attrs of the flow record: source/destination, Interface, Beyla IP, etc...
	Attrs RecordAttrs
}

type RecordAttrs struct {
	// SrcName and DstName might be set from several sources along the processing/decoration pipeline:
	// - K8s entity
	// - Host name
	// - IP
	SrcName string
	DstName string

	// SrcZone and DstZone represent the Cloud availability zones of the source and destination
	SrcZone string
	DstZone string

	Interface string
	// BeylaIP provides information about the source of the flow (the Agent that traced it)
	BeylaIP  string
	Metadata map[attr.Name]string
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

// SrcIP is never null. Returned as pointer for efficiency.
func (fi *NetFlowId) SrcIP() *IPAddr {
	return (*IPAddr)(&fi.SrcIp.In6U.U6Addr8)
}

// DstIP is never null. Returned as pointer for efficiency.
func (fi *NetFlowId) DstIP() *IPAddr {
	return (*IPAddr)(&fi.DstIp.In6U.U6Addr8)
}

// IP returns the net.IP equivalent object
func (ia *IPAddr) IP() net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise it would just encode the
// last 4 bytes of an IPv6 address
func (ia *IPAddr) IntEncodeV4() uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ia.IP().String() + `"`), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (NetFlowRecordT, error) {
	var fr NetFlowRecordT
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return fr, err
}
