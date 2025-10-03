// Copyright 2025 VMware, Inc.
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
	"encoding/binary"
	"fmt"
	"time"

	"github.com/vmware/go-ipfix/pkg/entities"
)

// BufferedIPFIXExporter wraps an ExportingProcess instance and supports buffering data records
// before sending them. BufferedIPFIXExporter is not safe for usage by multiple goroutines. There
// should be a single BufferedIPFIXExporter created for a given ExportingProcess.
// While the BufferedIPFIXExporter supports sending JSON records, in that case it mostly acts as a
// passthrough to the underlying ExportingProcess (no actual buffering).
type BufferedIPFIXExporter struct {
	ep          *ExportingProcess
	templateSet entities.Set
	// maps templateID to the corresponding buffer for data records. Note that entries are never
	// deleted from this map.
	messages   map[uint16]*bufferedMessage
	jsonBuffer bytes.Buffer
}

type bufferedMessage struct {
	ep         *ExportingProcess
	templateID uint16
	buffer     []byte
	numRecords int
}

func newBufferedMessage(ep *ExportingProcess, templateID uint16) *bufferedMessage {
	m := &bufferedMessage{
		ep:         ep,
		templateID: templateID,
		buffer:     make([]byte, 0, ep.maxMsgSize),
		numRecords: 0,
	}
	m.reset()
	return m
}

// NewBufferedIPFIXExporter creates a BufferedIPFIXExporter .
func NewBufferedIPFIXExporter(ep *ExportingProcess) *BufferedIPFIXExporter {
	bufferedExporter := &BufferedIPFIXExporter{
		ep:          ep,
		templateSet: entities.NewSet(false),
	}
	if !ep.sendJSONRecord {
		bufferedExporter.messages = make(map[uint16]*bufferedMessage)
	}
	return bufferedExporter
}

func (e *BufferedIPFIXExporter) addTemplateRecord(record entities.Record) error {
	templateID := record.GetTemplateID()
	// If the templateID already exists, we should send corresponding buffered data records
	// immediately, as they may not match the new template definition.
	if m, ok := e.messages[templateID]; ok {
		if err := m.flush(); err != nil {
			return fmt.Errorf("error when flushing buffered records for templateID %d: %w", templateID, err)
		}
	}
	e.templateSet.ResetSet()
	if err := e.templateSet.PrepareSet(entities.Template, entities.TemplateSetID); err != nil {
		return err
	}
	if err := e.templateSet.AddRecordV3(record); err != nil {
		return err
	}
	// It's important to use the method from ExporterProcess, for template management purposes.
	_, err := e.ep.SendSet(e.templateSet)
	return err
}

func (e *BufferedIPFIXExporter) addDataRecord(record entities.Record) error {
	templateID := record.GetTemplateID()
	m, ok := e.messages[templateID]
	if ok {
		return m.addRecord(record)
	}
	m = newBufferedMessage(e.ep, templateID)
	e.messages[templateID] = m
	return m.addRecord(record)
}

// AddRecord adds a record to be sent to the destination collector. If it is a template record, then
// it will be sent to the collector right away. If it is a data record, it will be added to the
// buffer. If adding the record to the buffer would cause the buffer length to exceed the max
// message size, the buffer is flushed first. Note that because data records are serialized to the
// buffer immediately, it is safe for the provided record to be mutated as soon as this function
// returns.
func (e *BufferedIPFIXExporter) AddRecord(record entities.Record) error {
	recordType := record.GetRecordType()
	switch recordType {
	case entities.Template:
		// We don't send templates for JSON records
		if e.ep.sendJSONRecord {
			return nil
		}
		return e.addTemplateRecord(record)
	case entities.Data:
		if e.ep.sendJSONRecord {
			_, _, err := e.ep.createAndSendJSONRecords([]entities.Record{record}, &e.jsonBuffer)
			return err
		}
		return e.addDataRecord(record)
	}
	return fmt.Errorf("invalid record type: %v", recordType)
}

// Flush sends all buffered data records immediately.
func (e *BufferedIPFIXExporter) Flush() error {
	if e.ep.sendJSONRecord {
		return nil
	}
	for _, m := range e.messages {
		if err := m.flush(); err != nil {
			return err
		}
	}
	return nil
}

func (m *bufferedMessage) addRecord(record entities.Record) error {
	recordLength := record.GetRecordLength()
	if len(m.buffer)+recordLength > m.ep.maxMsgSize {
		if m.numRecords == 0 {
			return fmt.Errorf("record is too big to fit into single message")
		}
		if _, err := m.sendMessage(); err != nil {
			return err
		}
	}
	var err error
	m.buffer, err = record.AppendToBuffer(m.buffer)
	if err != nil {
		return err
	}
	m.numRecords += 1
	return nil
}

func (m *bufferedMessage) flush() error {
	if m.numRecords == 0 {
		return nil
	}
	_, err := m.sendMessage()
	return err
}

func (m *bufferedMessage) reset() {
	const headerLength = entities.MsgHeaderLength + entities.SetHeaderLen
	m.buffer = m.buffer[:headerLength]
	m.numRecords = 0
}

func encodeMessageHeader(buf []byte, version, length uint16, exportTime, seqNumber, obsDomainID uint32) {
	bigEndian := binary.BigEndian
	bigEndian.PutUint16(buf, version)
	bigEndian.PutUint16(buf[2:], length)
	bigEndian.PutUint32(buf[4:], exportTime)
	bigEndian.PutUint32(buf[8:], seqNumber)
	bigEndian.PutUint32(buf[12:], obsDomainID)
}

func encodeSetHeader(buf []byte, templateID, length uint16) {
	bigEndian := binary.BigEndian
	bigEndian.PutUint16(buf, templateID)
	bigEndian.PutUint16(buf[2:], length)
}

func (m *bufferedMessage) sendMessage() (int, error) {
	now := time.Now()
	msgLen := len(m.buffer)
	encodeMessageHeader(m.buffer, 10, uint16(msgLen), uint32(now.Unix()), m.ep.seqNumber, m.ep.obsDomainID)
	encodeSetHeader(m.buffer[entities.MsgHeaderLength:], m.templateID, uint16(msgLen-entities.MsgHeaderLength))
	n, err := m.ep.connToCollector.Write(m.buffer)
	if err != nil {
		return n, err
	}
	m.ep.seqNumber = m.ep.seqNumber + uint32(m.numRecords)
	m.reset()
	return n, nil
}
