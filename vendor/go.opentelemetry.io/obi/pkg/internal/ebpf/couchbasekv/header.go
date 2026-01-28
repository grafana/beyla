// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv // import "go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"

import (
	"encoding/binary"
	"fmt"
)

// Offset represents a position in a packet buffer.
type Offset = int

// Header represents the common 24-byte memcached binary protocol header.
// The interpretation of bytes 6-7 differs between request (VBucket ID) and
// response (Status code) packets.
type Header struct {
	Magic     Magic
	Opcode    Opcode
	KeyLen    uint16
	ExtrasLen uint8
	DataType  DataType
	VBucketID uint16 // For requests: VBucket ID; For responses: Status code
	Status    Status // Alias for VBucketID when parsing responses
	BodyLen   uint32 // Total body length = extras + key + value
	Opaque    uint32 // Echoed back in response, like correlation ID
	CAS       uint64 // Compare-and-swap value
}

// TotalLen returns the total packet length (header + body).
func (h *Header) TotalLen() int {
	return HeaderLen + int(h.BodyLen)
}

// ValueLen returns the length of the value portion of the body.
func (h *Header) ValueLen() int {
	return int(h.BodyLen) - int(h.ExtrasLen) - int(h.KeyLen)
}

// Packet represents a parsed memcached binary protocol packet.
// If the packet data is truncated, as much as possible is parsed
// and the Truncated field is set to true.
type Packet struct {
	Header    Header
	Extras    []byte
	Key       []byte
	Value     []byte
	Truncated bool // True if the packet was truncated (incomplete body)
}

// ParseHeader parses a 24-byte memcached binary protocol header.
// It returns the parsed header and any error encountered.
func ParseHeader(pkt []byte) (*Header, error) {
	if len(pkt) < HeaderLen {
		return nil, fmt.Errorf("packet too short for header: got %d bytes, need %d", len(pkt), HeaderLen)
	}

	magic := Magic(pkt[0])
	if !magic.IsValid() {
		return nil, fmt.Errorf("invalid magic byte: 0x%02x", pkt[0])
	}

	header := &Header{
		Magic:     magic,
		Opcode:    Opcode(pkt[1]),
		KeyLen:    binary.BigEndian.Uint16(pkt[2:4]),
		ExtrasLen: pkt[4],
		DataType:  DataType(pkt[5]),
		BodyLen:   binary.BigEndian.Uint32(pkt[8:12]),
		Opaque:    binary.BigEndian.Uint32(pkt[12:16]),
		CAS:       binary.BigEndian.Uint64(pkt[16:24]),
	}

	// Bytes 6-7 interpretation depends on packet type
	if magic.IsRequest() {
		header.VBucketID = binary.BigEndian.Uint16(pkt[6:8])
	} else {
		header.Status = Status(binary.BigEndian.Uint16(pkt[6:8]))
	}

	if err := validateHeader(header); err != nil {
		return nil, err
	}

	return header, nil
}

// ParsePacket parses a memcached binary protocol packet including the header
// and body (extras, key, value). If the packet is truncated, it parses as much
// as possible and sets the Truncated field to true.
func ParsePacket(pkt []byte) (*Packet, error) {
	header, err := ParseHeader(pkt)
	if err != nil {
		return nil, err
	}

	packet := &Packet{
		Header: *header,
	}

	available := len(pkt) - HeaderLen
	needed := int(header.BodyLen)

	if available < needed {
		packet.Truncated = true
	}

	offset := HeaderLen
	remaining := len(pkt) - offset

	// Parse extras (or as much as available)
	if header.ExtrasLen > 0 {
		extrasLen := int(header.ExtrasLen)
		if remaining < extrasLen {
			extrasLen = remaining
		}
		if extrasLen > 0 {
			packet.Extras = pkt[offset : offset+extrasLen]
			offset += extrasLen
			remaining = len(pkt) - offset
		}
	}

	// Parse key (or as much as available)
	if header.KeyLen > 0 {
		keyLen := int(header.KeyLen)
		if remaining < keyLen {
			keyLen = remaining
		}
		if keyLen > 0 {
			packet.Key = pkt[offset : offset+keyLen]
			offset += keyLen
			remaining = len(pkt) - offset
		}
	}

	// Parse value (or as much as available)
	valueLen := header.ValueLen()
	if valueLen > 0 {
		if remaining < valueLen {
			valueLen = remaining
		}
		if valueLen > 0 {
			packet.Value = pkt[offset : offset+valueLen]
		}
	}

	return packet, nil
}

// ParsePackets parses multiple memcached packets from a single byte slice,
// as there may be pipelined requests or responses in one TCP segment.
func ParsePackets(segment []byte) ([]*Packet, error) {
	var packets []*Packet
	offset := 0

	for offset < len(segment) {
		remaining := segment[offset:]
		if len(remaining) < HeaderLen {
			// Not enough data for another header
			break
		}

		packet, err := ParsePacket(remaining)
		if err != nil {
			return packets, err
		}

		packets = append(packets, packet)
		offset += packet.Header.TotalLen()
	}

	return packets, nil
}

// validateHeader checks for basic validity of the parsed header.
func validateHeader(h *Header) error {
	// Check that body length is consistent with extras and key length
	if int(h.BodyLen) < int(h.ExtrasLen)+int(h.KeyLen) {
		return fmt.Errorf("invalid body length: %d < extras(%d) + key(%d)",
			h.BodyLen, h.ExtrasLen, h.KeyLen)
	}

	return nil
}

// IsRequest returns true if this packet is a request.
func (p *Packet) IsRequest() bool {
	return p.Header.Magic.IsRequest()
}

// IsResponse returns true if this packet is a response.
func (p *Packet) IsResponse() bool {
	return p.Header.Magic.IsResponse()
}

// KeyString returns the key as a string.
func (p *Packet) KeyString() string {
	return string(p.Key)
}

// ValueString returns the value as a string.
func (p *Packet) ValueString() string {
	return string(p.Value)
}

// ExtrasString returns the extras as a string.
func (p *Packet) ExtrasString() string {
	return string(p.Extras)
}

// IsComplete returns true if the packet body was fully parsed (not truncated).
func (p *Packet) IsComplete() bool {
	return !p.Truncated
}

// HasFullKey returns true if the complete key was parsed.
func (p *Packet) HasFullKey() bool {
	return len(p.Key) == int(p.Header.KeyLen)
}

// HasFullExtras returns true if the complete extras were parsed.
func (p *Packet) HasFullExtras() bool {
	return len(p.Extras) == int(p.Header.ExtrasLen)
}

// HasFullValue returns true if the complete value was parsed.
func (p *Packet) HasFullValue() bool {
	return len(p.Value) == p.Header.ValueLen()
}
