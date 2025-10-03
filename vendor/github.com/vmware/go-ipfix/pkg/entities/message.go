// Copyright 2020 VMware, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package entities

import (
	"encoding/binary"
)

const (
	MaxSocketMsgSize = 65535
	MsgHeaderLength  = 16
	// Typically all networks should support a datagram size of 512B without fragmentation.
	MinSupportedMsgSize = 512
)

// Message represents IPFIX message.
// TODO: Currently, it supports only one set. This will be extended to support multiple
// sets.
type Message struct {
	msgHeader     []byte
	version       uint16
	length        uint16
	seqNumber     uint32
	obsDomainID   uint32
	exportTime    uint32
	exportAddress string
	isDecoding    bool
	set           Set
}

func NewMessage(isDecoding bool) *Message {
	return &Message{
		msgHeader:  make([]byte, MsgHeaderLength),
		isDecoding: isDecoding,
	}
}

func (m *Message) GetVersion() uint16 {
	return m.version
}

func (m *Message) SetVersion(version uint16) {
	m.version = version
	if !m.isDecoding {
		binary.BigEndian.PutUint16(m.msgHeader[0:2], version)
	}
}

func (m *Message) GetMessageLen() uint16 {
	return m.length
}

func (m *Message) SetMessageLen(len uint16) {
	m.length = len
	if !m.isDecoding {
		binary.BigEndian.PutUint16(m.msgHeader[2:4], len)
	}
}

func (m *Message) GetSequenceNum() uint32 {
	return m.seqNumber
}

func (m *Message) SetSequenceNum(seqNum uint32) {
	m.seqNumber = seqNum
	if !m.isDecoding {
		binary.BigEndian.PutUint32(m.msgHeader[8:12], seqNum)
	}
}

func (m *Message) GetObsDomainID() uint32 {
	return m.obsDomainID
}

func (m *Message) SetObsDomainID(obsDomainID uint32) {
	m.obsDomainID = obsDomainID
	if !m.isDecoding {
		binary.BigEndian.PutUint32(m.msgHeader[12:], obsDomainID)
	}
}

func (m *Message) GetExportTime() uint32 {
	return m.exportTime
}

func (m *Message) SetExportTime(exportTime uint32) {
	m.exportTime = exportTime
	if !m.isDecoding {
		binary.BigEndian.PutUint32(m.msgHeader[4:8], exportTime)
	}
}

func (m *Message) GetExportAddress() string {
	return m.exportAddress
}

func (m *Message) SetExportAddress(ipAddr string) {
	m.exportAddress = ipAddr
}

func (m *Message) GetSet() Set {
	return m.set
}

func (m *Message) AddSet(set Set) {
	m.set = set
}

func (m *Message) GetMsgHeader() []byte {
	return m.msgHeader
}

func (m *Message) ResetMsgHeader() {
	clear(m.msgHeader)
}
