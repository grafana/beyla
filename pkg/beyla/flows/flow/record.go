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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
const (
	DirectionIngress = uint8(0)
	DirectionEgress  = uint8(1)
)
const MacLen = 6

// IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const IPv6Type = 0x86DD

type HumanBytes uint64
type MacAddr [MacLen]uint8
type Direction uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type DataLink struct {
	SrcMac MacAddr
	DstMac MacAddr
}

type Network struct {
	SrcAddr IPAddr
	DstAddr IPAddr
}

type Transport struct {
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8 `json:"Proto"`
}

// RecordKey identifies a flow
// Must coincide byte by byte with kernel-side flow_id_t (bpf/flow.h)
// TODO: let cilium bpf2go create this
type RecordKey struct {
	EthProtocol uint16 `json:"Etype"`
	Direction   uint8  `json:"FlowDirection"`
	DataLink
	Network
	Transport
	IFIndex uint32
}

// RecordMetrics provides flows metrics and timing information
// Must coincide byte by byte with kernel-side flow_metrics_t (bpf/flow.h)
type RecordMetrics struct {
	Packets uint32
	Bytes   uint64
	// StartMonoTimeNs and EndMonoTimeNs are the start and end times as system monotonic timestamps
	// in nanoseconds, as output from bpf_ktime_get_ns() (kernel space)
	// and monotime.Now() (user space)
	StartMonoTimeNs uint64
	EndMonoTimeNs   uint64
	Flags           uint16
	Errno           uint8
}

// record structure as parsed from eBPF
// it's important to emphasize that the fields in this structure have to coincide,
// byte by byte, with the flow_record_t structure in the bpf/flow.h file
type RawRecord struct {
	RecordKey
	RecordMetrics
}

// Record contains accumulated metrics from a flow
type Record struct {
	RawRecord
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
}

func NewRecord(
	key RecordKey,
	metrics RecordMetrics,
	currentTime time.Time,
	monotonicCurrentTime uint64,
) *Record {
	startDelta := time.Duration(monotonicCurrentTime - metrics.StartMonoTimeNs)
	endDelta := time.Duration(monotonicCurrentTime - metrics.EndMonoTimeNs)
	return &Record{
		RawRecord: RawRecord{
			RecordKey:     key,
			RecordMetrics: metrics,
		},
		TimeFlowStart: currentTime.Add(-startDelta),
		TimeFlowEnd:   currentTime.Add(-endDelta),
	}
}

func (r *RecordMetrics) Accumulate(src *RecordMetrics) {
	// time == 0 if the value has not been yet set
	if r.StartMonoTimeNs == 0 || r.StartMonoTimeNs > src.StartMonoTimeNs {
		r.StartMonoTimeNs = src.StartMonoTimeNs
	}
	if r.EndMonoTimeNs == 0 || r.EndMonoTimeNs < src.EndMonoTimeNs {
		r.EndMonoTimeNs = src.EndMonoTimeNs
	}
	r.Bytes += src.Bytes
	r.Packets += src.Packets
	r.Flags |= src.Flags
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
func ReadFrom(reader io.Reader) (*RawRecord, error) {
	var fr RawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &fr, err
}
