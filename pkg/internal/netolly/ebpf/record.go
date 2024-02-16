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
	"fmt"
	"io"
	"net"
	"time"
)

const MacLen = 6

type MacAddr [MacLen]uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

// Record contains accumulated metrics from a flow, with extra metadata
// that is added from the user space
type Record struct {
	NetFlowRecordT
	// TODO: redundant field from RecordMetrics. Reorganize structs
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	Interface     string
	// Duplicate tells whether this flow has another duplicate so it has to be excluded from
	// any metrics' aggregation (e.g. bytes/second rates between two pods).
	// The reason for this field is that the same flow can be observed from multiple interfaces,
	// so the agent needs to choose only a view of the same flow and mark the others as
	// "exclude from aggregation". Otherwise rates, sums, etc... values would be multiplied by the
	// number of interfaces this flow is observed from.
	Duplicate bool

	// AgentIP provides information about the source of the flow (the Agent that traced it)
	AgentIP string

	Metadata map[string]string
}

func NewRecord(
	key NetFlowId,
	metrics NetFlowMetrics,
	currentTime time.Time,
	monotonicCurrentTime uint64,
) *Record {
	startDelta := time.Duration(monotonicCurrentTime - metrics.StartMonoTimeNs)
	endDelta := time.Duration(monotonicCurrentTime - metrics.EndMonoTimeNs)
	return &Record{
		NetFlowRecordT: NetFlowRecordT{
			Id:      key,
			Metrics: metrics,
		},
		TimeFlowStart: currentTime.Add(-startDelta),
		TimeFlowEnd:   currentTime.Add(-endDelta),
	}
}

func (fm *NetFlowMetrics) Accumulate(src *NetFlowMetrics) {
	// time == 0 if the value has not been yet set
	if fm.StartMonoTimeNs == 0 || fm.StartMonoTimeNs > src.StartMonoTimeNs {
		fm.StartMonoTimeNs = src.StartMonoTimeNs
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

// SrcMAC is never null. Returned as pointer for efficiency.
func (fi *NetFlowId) SrcMAC() *MacAddr {
	return (*MacAddr)(&fi.SrcMac)
}

// DstMAC is never null. Returned as pointer for efficiency.
func (fi *NetFlowId) DstMAC() *MacAddr {
	return (*MacAddr)(&fi.DstMac)
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

func (m *MacAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*NetFlowRecordT, error) {
	var fr NetFlowRecordT
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &fr, err
}
