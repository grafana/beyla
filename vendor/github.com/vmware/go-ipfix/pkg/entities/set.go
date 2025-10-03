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
	"fmt"
)

//go:generate mockgen -copyright_file ../../license_templates/license_header.raw.txt -destination=testing/mock_set.go -package=testing github.com/vmware/go-ipfix/pkg/entities Set

const (
	// TemplateRefreshTimeOut is the template refresh time out for exporting process
	// The default is based on https://datatracker.ietf.org/doc/html/rfc5153#section-6.2
	// and https://datatracker.ietf.org/doc/html/rfc6728#section-4.4.2
	TemplateRefreshTimeOut uint32 = 600
	// TemplateTTL is the template time to live for collecting process
	// See https://datatracker.ietf.org/doc/html/rfc6728#section-4.5.2
	TemplateTTL = TemplateRefreshTimeOut * 3
	// TemplateSetID is the setID for template record
	TemplateSetID uint16 = 2
	SetHeaderLen  int    = 4
)

// ContenType is used for both sets and records.
type ContentType uint8

const (
	Template ContentType = iota
	Data
	// Add OptionsTemplate too when it is supported
	Undefined = 255
)

type Set interface {
	PrepareSet(setType ContentType, templateID uint16) error
	// Call ResetSet followed by a new call to PrepareSet in order to reuse an existing Set,
	// instead of instantiating a new one.
	ResetSet()
	GetHeaderBuffer() []byte
	GetSetLength() int
	GetSetType() ContentType
	UpdateLenInHeader()
	AddRecord(elements []InfoElementWithValue, templateID uint16) error
	AddRecordWithExtraElements(elements []InfoElementWithValue, numExtraElements int, templateID uint16) error
	// Unlike AddRecord, AddRecordV2 uses the elements slice directly, instead of creating a new
	// one. This can result in fewer memory allocations. The caller should not modify the
	// contents of the slice after calling AddRecordV2.
	AddRecordV2(elements []InfoElementWithValue, templateID uint16) error
	// Unlike other AddRecord* variants, AddRecordV3 takes an actual existing Record as an input
	// parameter, instead of a list of Information Elements with values. When calling
	// AddRecordV3, the Set effectively takes ownership of the Record, and the Record should no
	// longer be modified by the caller.
	AddRecordV3(record Record) error
	GetRecords() []Record
	GetNumberOfRecords() uint32
}

type set struct {
	headerBuffer []byte
	setType      ContentType
	templateID   uint16
	records      []Record
	isDecoding   bool
	length       int
}

func NewSet(isDecoding bool) *set {
	if isDecoding {
		return &set{
			records:    make([]Record, 0),
			isDecoding: isDecoding,
		}
	} else {
		return &set{
			headerBuffer: make([]byte, SetHeaderLen),
			records:      make([]Record, 0),
			isDecoding:   isDecoding,
			length:       SetHeaderLen,
		}
	}
}

func (s *set) PrepareSet(setType ContentType, templateID uint16) error {
	if setType == Undefined {
		return fmt.Errorf("set type is not properly defined")
	} else {
		s.setType = setType
	}
	s.templateID = templateID
	if !s.isDecoding {
		// Create the set header and append it when encoding
		s.createHeader(s.setType, templateID)
	}
	return nil
}

func (s *set) ResetSet() {
	if s.isDecoding {
		s.length = 0
	} else {
		clear(s.headerBuffer)
		s.length = SetHeaderLen
	}
	s.setType = Undefined
	// Clear before shrinking the slice so that existing elements are eligible for garbage collection.
	clear(s.records)
	// Shrink the slice: the slice capacity is preserved.
	s.records = s.records[:0]
}

func (s *set) GetHeaderBuffer() []byte {
	return s.headerBuffer
}

func (s *set) GetSetLength() int {
	return s.length
}

func (s *set) GetSetType() ContentType {
	return s.setType
}

func (s *set) UpdateLenInHeader() {
	// TODO:Add padding to the length when multiple sets are sent in IPFIX message
	if !s.isDecoding {
		// Add length to the set header
		binary.BigEndian.PutUint16(s.headerBuffer[2:4], uint16(s.length))
	}
}

func (s *set) AddRecord(elements []InfoElementWithValue, templateID uint16) error {
	return s.AddRecordWithExtraElements(elements, 0, templateID)
}

func (s *set) AddRecordWithExtraElements(elements []InfoElementWithValue, numExtraElements int, templateID uint16) error {
	var record Record
	switch s.setType {
	case Data:
		record = NewDataRecord(templateID, len(elements), numExtraElements)
	case Template:
		record = NewTemplateRecord(templateID, len(elements))
		err := record.PrepareRecord()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("set type is not supported")
	}
	for i := range elements {
		err := record.AddInfoElement(elements[i])
		if err != nil {
			return err
		}
	}
	s.records = append(s.records, record)
	s.length += record.GetRecordLength()
	return nil
}

func (s *set) AddRecordV2(elements []InfoElementWithValue, templateID uint16) error {
	var record Record
	switch s.setType {
	case Data:
		record = NewDataRecordFromElements(templateID, elements)
	case Template:
		record = NewTemplateRecordFromElements(templateID, elements)
		err := record.PrepareRecord()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("set type is not supported")
	}
	s.records = append(s.records, record)
	s.length += record.GetRecordLength()
	return nil
}

func (s *set) AddRecordV3(record Record) error {
	// Sanity check: we need to make sure that the record is allowed to be added.
	recordType := record.GetRecordType()
	if recordType != s.setType {
		return fmt.Errorf("record and set types don't match")
	}
	if recordType == Data && record.GetTemplateID() != s.templateID {
		return fmt.Errorf("all data records in the same data set must have the same template ID")
	}
	s.records = append(s.records, record)
	s.length += record.GetRecordLength()
	return nil
}

func (s *set) GetRecords() []Record {
	return s.records
}

func (s *set) GetNumberOfRecords() uint32 {
	return uint32(len(s.records))
}

func (s *set) createHeader(setType ContentType, templateID uint16) {
	switch setType {
	case Template:
		binary.BigEndian.PutUint16(s.headerBuffer[0:2], TemplateSetID)
	case Data:
		binary.BigEndian.PutUint16(s.headerBuffer[0:2], templateID)
	}
}

// MakeTemplateSet is a convenience function which creates a template Set with a single Record.
func MakeTemplateSet(templateID uint16, ies []*InfoElement) (*set, error) {
	tempSet := NewSet(false)
	if err := tempSet.PrepareSet(Template, TemplateSetID); err != nil {
		return nil, err
	}
	elements := make([]InfoElementWithValue, len(ies))
	for idx, ie := range ies {
		var err error
		if elements[idx], err = DecodeAndCreateInfoElementWithValue(ie, nil); err != nil {
			return nil, err
		}
	}
	if err := tempSet.AddRecord(elements, templateID); err != nil {
		return nil, err
	}
	return tempSet, nil
}

// MakeDataSet is a convenience function which creates a data Set with a single Record.
func MakeDataSet(templateID uint16, ies []InfoElementWithValue) (*set, error) {
	dataSet := NewSet(false)
	if err := dataSet.PrepareSet(Data, templateID); err != nil {
		return nil, err
	}
	if err := dataSet.AddRecord(ies, templateID); err != nil {
		return nil, err
	}
	return dataSet, nil
}
