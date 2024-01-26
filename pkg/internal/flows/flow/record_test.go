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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordBinaryEncoding(t *testing.T) {
	// Makes sure that we read the C *packed* flow structure according
	// to the order defined in bpf/flow.h
	fr, err := ReadFrom(bytes.NewReader([]byte{
		0x01, 0x02, // u16 eth_protocol
		0x03,                               // u16 direction
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // data_link: u8[6] src_mac
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // data_link: u8[6] dst_mac
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09, // network: u8[16] src_ip
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, // network: u32 dst_ip
		0x0e, 0x0f, // transport: u16 src_port
		0x10, 0x11, // transport: u16 dst_port
		0x12,                   // transport: u8 transport_protocol
		0x13, 0x14, 0x15, 0x16, // interface index
		0x06, 0x07, 0x08, 0x09, // u32 packets
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 bytes
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_start_time
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_end_time
		0x13, 0x14, //flags
		0x33, // u8 errno

	}))
	require.NoError(t, err)

	assert.Equal(t, RawRecord{
		RecordKey: RecordKey{
			EthProtocol: 0x0201,
			Direction:   0x03,
			DataLink: DataLink{
				SrcMac: MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
				DstMac: MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			},
			Network: Network{
				SrcAddr: IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
				DstAddr: IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
			},
			Transport: Transport{
				SrcPort:  0x0f0e,
				DstPort:  0x1110,
				Protocol: 0x12,
			},
			IFIndex: 0x16151413,
		},
		RecordMetrics: RecordMetrics{
			Packets:         0x09080706,
			Bytes:           0x1a19181716151413,
			StartMonoTimeNs: 0x1a19181716151413,
			EndMonoTimeNs:   0x1a19181716151413,
			Flags:           0x1413,
			Errno:           0x33,
		},
	}, *fr)
	// assert that IP addresses are interpreted as IPv4 addresses
	assert.Equal(t, "6.7.8.9", fr.Network.SrcAddr.IP().String())
	assert.Equal(t, "10.11.12.13", fr.Network.DstAddr.IP().String())
}
