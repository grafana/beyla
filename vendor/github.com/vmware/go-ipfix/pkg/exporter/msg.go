// Copyright 2023 VMware, Inc.
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

package exporter

import (
	"bytes"
	"fmt"
	"time"

	"github.com/vmware/go-ipfix/pkg/entities"
)

func CreateIPFIXMsg(set entities.Set, obsDomainID uint32, seqNumber uint32, exportTime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := WriteIPFIXMsgToBuffer(set, obsDomainID, seqNumber, exportTime, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// WriteIPFIXMsgToBuffer serializes the set as an IPFIX message and writes it to the provided
// buffer. It returns the message length and an error if applicable.
func WriteIPFIXMsgToBuffer(set entities.Set, obsDomainID uint32, seqNumber uint32, exportTime time.Time, buf *bytes.Buffer) (int, error) {
	// Create a new message and use it to send the set.
	msg := entities.NewMessage(false)

	// Check if message is exceeding the limit after adding the set. Include message
	// header length too.
	msgLen := entities.MsgHeaderLength + set.GetSetLength()
	if msgLen > entities.MaxSocketMsgSize {
		// This is applicable for both TCP and UDP sockets.
		return 0, fmt.Errorf("message size exceeds max socket buffer size")
	}

	// Set the fields in the message header.
	// IPFIX version number is 10.
	// https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-version-numbers
	msg.SetVersion(10)
	msg.SetObsDomainID(obsDomainID)
	msg.SetMessageLen(uint16(msgLen))
	msg.SetExportTime(uint32(exportTime.Unix()))
	msg.SetSequenceNum(seqNumber)

	buf.Grow(msgLen)
	buf.Write(msg.GetMsgHeader())
	buf.Write(set.GetHeaderBuffer())
	b := buf.AvailableBuffer()
	for _, record := range set.GetRecords() {
		var err error
		// Calls to AppendToBuffer won't cause memory allocations as the
		// buffer is already guaranteed to have enough capacity.
		b, err = record.AppendToBuffer(b)
		if err != nil {
			return 0, err
		}
	}
	buf.Write(b)

	return msgLen, nil
}
