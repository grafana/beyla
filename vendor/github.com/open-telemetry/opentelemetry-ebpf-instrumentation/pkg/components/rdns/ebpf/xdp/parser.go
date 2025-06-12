// Package xdp provides DNS message parsing functionality for the XDP-based DNS response tracker.
package xdp

import (
	"bytes"
	"encoding/binary"
)

// wordSize represents the size of a DNS message word (2 bytes)
const wordSize = 2

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
	questions := make([]*question, 0, qdcount)
	for i := uint16(0); i < qdcount; i++ {
		q := parseQSection(data)
		if q == nil {
			break
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

	s.qName = parseSectionLabel(data)

	if s.qName == "" {
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
// Returns an empty string if the label sequence is malformed.
func parseSectionLabel(data *bytes.Buffer) string {
	var label string

	sep := ""

	for {
		if data.Len() == 0 {
			return ""
		}

		labelLen := int(readByte(data))

		if labelLen == 0 {
			break
		}

		label += sep + string(data.Next(labelLen))

		sep = "."
	}

	return label
}

// parseRecords parses the answer records section of a DNS message.
// It processes the specified number of records and returns them as a slice.
// Returns nil if any record is malformed.
func parseRecords(data *bytes.Buffer, base []byte, count uint16) []*record {
	records := make([]*record, 0, count)

	for i := uint16(0); i < count; i++ {
		r := parseRecord(data, base)
		if r == nil {
			break
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

		if uint16(len(base)) < offset {
			return nil
		}

		r.name = parseSectionLabel(bytes.NewBuffer(base[offset:]))
	} else {
		_ = data.UnreadByte()
		r.name = parseSectionLabel(data)
	}

	if data.Len() < 5*wordSize {
		return nil
	}

	r.typ = binary.BigEndian.Uint16(readWord(data))
	r.class = binary.BigEndian.Uint16(readWord(data))
	r.ttl = binary.BigEndian.Uint32(readDWord(data))
	rdlength := binary.BigEndian.Uint16(readWord(data))

	if data.Len() < 0 || uint16(data.Len()) < rdlength {
		return nil
	}

	r.data = data.Next(int(rdlength))

	return &r
}
