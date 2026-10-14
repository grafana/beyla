// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package xdp provides DNS message parsing functionality for the XDP-based DNS response tracker.
package xdp // import "go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"

import (
	"bytes"
	"encoding/binary"
	"strings"
)

const (
	// wordSize represents the size of a DNS message word (2 bytes)
	wordSize = 2

	maxLabelLength    = 63
	maxNameLength     = 255
	minQuestionLength = 1 + 2*wordSize
	minRecordLength   = 1 + 5*wordSize
)

// readByte reads and returns a single byte from the buffer
func readByte(b *bytes.Buffer) byte {
	u, _ := b.ReadByte()
	return u
}

// readWord reads and returns a 2-byte word from the buffer
func readWord(b *bytes.Buffer) []byte {
	return b.Next(wordSize)
}

// readDWord reads and returns a 4-byte double word from the buffer
func readDWord(b *bytes.Buffer) []byte {
	return b.Next(2 * wordSize)
}

func sectionCapacity(count uint16, remaining, minimumLength int) int {
	return min(int(count), remaining/minimumLength)
}

// parseDNSMessage parses a raw DNS message into a structured dnsMessage object.
// It handles the DNS message header, questions, and answer sections.
// Returns nil if the message is malformed or incomplete.
func parseDNSMessage(rawData []byte) *dnsMessage {
	data := bytes.NewBuffer(rawData)

	if data.Len() < wordSize {
		return nil
	}

	r := dnsMessage{}

	r.id = binary.BigEndian.Uint16(readWord(data))

	if data.Len() < wordSize {
		return nil
	}

	r.flagsHi = readByte(data)
	r.flagsLo = readByte(data)

	if data.Len() < 4*wordSize {
		return nil
	}

	qdcount := binary.BigEndian.Uint16(readWord(data))
	ancount := binary.BigEndian.Uint16(readWord(data))
	nscount := binary.BigEndian.Uint16(readWord(data))
	arcount := binary.BigEndian.Uint16(readWord(data))
	_, _ = nscount, arcount

	r.questions = parseQSections(data, qdcount)

	if len(r.questions) == 0 {
		return nil
	}

	r.answers = parseRecords(data, rawData, ancount)

	if len(r.answers) == 0 {
		return nil
	}

	return &r
}

// parseQSections parses the question section of a DNS message.
// It processes the specified number of questions and returns them as a slice.
// Returns nil if any question is malformed.
func parseQSections(data *bytes.Buffer, qdcount uint16) []*question {
	questions := make([]*question, 0, sectionCapacity(qdcount, data.Len(), minQuestionLength))
	for range qdcount {
		q := parseQSection(data)
		if q == nil {
			return nil
		}
		questions = append(questions, q)
	}
	return questions
}

// parseQSection parses a single question section from a DNS message.
// It extracts the query name, type, and class.
// Returns nil if the section is malformed.
func parseQSection(data *bytes.Buffer) *question {
	s := question{}

	var valid bool
	s.qName, valid = parseSectionLabel(data)

	if !valid || s.qName == "" {
		return nil
	}

	if data.Len() < 2*wordSize {
		return nil
	}

	s.qType = binary.BigEndian.Uint16(readWord(data))
	s.qClass = binary.BigEndian.Uint16(readWord(data))

	return &s
}

// parseSectionLabel parses a DNS label sequence from the buffer.
// Labels are separated by dots and terminated by a zero-length label.
// Returns false if the label sequence is malformed.
func parseSectionLabel(data *bytes.Buffer) (string, bool) {
	var labelBuilder strings.Builder

	sep := ""
	nameLength := 0

	for {
		if data.Len() == 0 {
			return "", false
		}

		labelLen := int(readByte(data))
		nameLength++
		if nameLength > maxNameLength {
			return "", false
		}

		if labelLen == 0 {
			break
		}

		if labelLen > maxLabelLength || data.Len() < labelLen || nameLength+labelLen > maxNameLength {
			return "", false
		}

		labelBuilder.WriteString(sep)
		labelBuilder.Write(data.Next(labelLen))
		nameLength += labelLen

		sep = "."
	}

	return labelBuilder.String(), true
}

// parseRecords parses the answer records section of a DNS message.
// It processes the specified number of records and returns them as a slice.
// Returns nil if any record is malformed.
func parseRecords(data *bytes.Buffer, base []byte, count uint16) []*record {
	records := make([]*record, 0, sectionCapacity(count, data.Len(), minRecordLength))

	for range count {
		r := parseRecord(data, base)
		if r == nil {
			return nil
		}
		records = append(records, r)
	}

	return records
}

// parseRecord parses a single DNS resource record from the buffer.
// It handles both normal and compressed labels, and extracts record type,
// class, TTL, and record data.
// Returns nil if the record is malformed.
func parseRecord(data *bytes.Buffer, base []byte) *record {
	if data.Len() == 0 {
		return nil
	}

	r := record{}
	validName := false

	labelLen := readByte(data)

	// we have a compressed label
	if (labelLen & 0xc0) == 0xc0 {
		if data.Len() == 0 {
			return nil
		}

		labelLen &= 0x3f
		lenLo := readByte(data)

		offsetBe := []byte{labelLen, lenLo}
		offset := binary.BigEndian.Uint16(offsetBe)

		if int(offset) >= len(base) {
			return nil
		}

		r.name, validName = parseSectionLabel(bytes.NewBuffer(base[offset:]))
	} else {
		_ = data.UnreadByte()
		r.name, validName = parseSectionLabel(data)
	}

	if !validName {
		return nil
	}

	if data.Len() < 5*wordSize {
		return nil
	}

	r.typ = binary.BigEndian.Uint16(readWord(data))
	r.class = binary.BigEndian.Uint16(readWord(data))
	r.ttl = binary.BigEndian.Uint32(readDWord(data))
	rdlength := binary.BigEndian.Uint16(readWord(data))

	if data.Len() < int(rdlength) {
		return nil
	}

	r.data = data.Next(int(rdlength))

	return &r
}
