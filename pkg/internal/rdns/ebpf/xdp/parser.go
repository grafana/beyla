package xdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const DEBUG_PARSER = false

func parserDebug(format string, a ...any) {
	if (DEBUG_PARSER) {
		fmt.Printf(format, a...)
	}
}

const wordSize = 2

func readByte(b *bytes.Buffer) byte {
	u, _ := b.ReadByte()
	return u
}

func readWord(b *bytes.Buffer) []byte {
	return b.Next(wordSize)
}

func readDWord(b *bytes.Buffer) []byte {
	return b.Next(2 * wordSize)
}

func parseDNSMessage(rawData []byte) *dnsMessage {
	data := bytes.NewBuffer(rawData)

	if (data.Len() < wordSize) {
		return nil
	}

	r := dnsMessage{}

	r.id = binary.BigEndian.Uint16(readWord(data))

	if (data.Len() < wordSize) {
		return nil
	}

	r.flagsHi = readByte(data)
	r.flagsLo = readByte(data)

	parserDebug("ID: %x, qr: %t, op: %d, aa: %t, tc: %t, rd: %t, ra: %t, z: %d, rcode: %d\n",
		r.Id(), r.IsQuery(), r.Opcode(), r.AuthoritativeAnswer(), r.Truncation(),
		r.RecursionDesired(), r.RecursionAvailable(), r.Z(), r.RCode())

	if data.Len() < 4 *wordSize {
		return nil
	}

	qdcount := binary.BigEndian.Uint16(readWord(data))
	ancount := binary.BigEndian.Uint16(readWord(data))
	nscount := binary.BigEndian.Uint16(readWord(data))
	arcount := binary.BigEndian.Uint16(readWord(data))

	parserDebug("qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n",
		qdcount, ancount, nscount, arcount)

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

func parseQSections(data *bytes.Buffer, qdcount uint16) []*question {
	questions := make([]*question, 0, qdcount)

	for i := uint16(0); i < qdcount; i++ {
		var q *question

		q = parseQSection(data)

		if q == nil {
			return nil
		}

		questions = append(questions, q)

		parserDebug("Section name: %s, type: %d, class: %d\n", q.qName, q.qType, q.qClass)
	}

	return questions
}

func parseQSection(data *bytes.Buffer) *question {
	s := question{}

	s.qName = parseSectionLabel(data)

	if s.qName == "" {
		return nil
	}

	if data.Len() < 2 *wordSize {
		return nil
	}

	s.qType = binary.BigEndian.Uint16(readWord(data))
	s.qClass = binary.BigEndian.Uint16(readWord(data))

	return &s
}

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

func parseRecords(data *bytes.Buffer, base []byte, count uint16) []*record {
	records := make([]*record, 0, count)

	for i := uint16(0); i < count; i++ {
		var r *record

		r = parseRecord(data, base)

		if r == nil {
			parserDebug("Error parsing record\n")
			return nil
		}

		records = append(records, r)

		parserDebug("Record name: %s, type: %d, class: %d, data: %v\n",
			r.name, r.typ, r.class, r.data)
	}

	return records
}

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

		offsetBe := []byte { labelLen, lenLo }
		offset := binary.BigEndian.Uint16(offsetBe)

		if uint16(len(base)) < offset {
			return nil
		}

		r.name = parseSectionLabel(bytes.NewBuffer(base[offset:]))

		parserDebug("Parsed compressed label: %s\n", r.name)
	} else {
		data.UnreadByte()
		r.name = parseSectionLabel(data)

		parserDebug("Parsed normal label: %s\n", r.name)
	}

	if data.Len() < 5 *wordSize {
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
