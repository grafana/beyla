// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package mqttparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"

import (
	"errors"
	"fmt"
)

// PacketReader provides primitive binary reading operations for MQTT packets.
// It tracks the current offset automatically and is embedded by packet-specific
// readers (e.g., ConnectPacketReader) to provide domain-specific read methods.
type PacketReader struct {
	pkt    []byte
	offset int
}

// NewPacketReader creates a new PacketReader starting at the given offset.
func NewPacketReader(pkt []byte, offset int) PacketReader {
	return PacketReader{pkt: pkt, offset: offset}
}

// Offset returns the current position in the packet.
func (r *PacketReader) Offset() int {
	return r.offset
}

// SetOffset to a new position, useful for checkpoint/restore.
func (r *PacketReader) SetOffset(offset int) {
	r.offset = offset
}

// Remaining returns the number of bytes remaining in the packet.
func (r *PacketReader) Remaining() int {
	return len(r.pkt) - r.offset
}

// Skip advances the offset by n bytes.
func (r *PacketReader) Skip(n int) error {
	if r.offset+n > len(r.pkt) {
		return fmt.Errorf("not enough data to skip by %d bytes, remaining: %d", n, r.Remaining())
	}
	r.offset += n
	return nil
}

// ReadUint8 reads a single byte.
func (r *PacketReader) ReadUint8() (uint8, error) {
	if r.offset >= len(r.pkt) {
		return 0, errors.New("not enough data for uint8")
	}
	value := r.pkt[r.offset]
	r.offset++
	return value, nil
}

// ReadUint16 reads a big-endian 16-bit unsigned integer.
func (r *PacketReader) ReadUint16() (uint16, error) {
	if r.offset+2 > len(r.pkt) {
		return 0, errors.New("not enough data for uint16")
	}
	value := uint16(r.pkt[r.offset])<<8 | uint16(r.pkt[r.offset+1])
	r.offset += 2
	return value, nil
}

// ReadVariableByteInteger reads an MQTT variable byte integer.
// MQTT variable-length encoding (MQTT 5.0 spec, section 1.5.5):
//   - Each byte encodes 7 bits of data (bits 0-6)
//   - Bit 7 (0x80) is the continuation bit: 1 = more bytes follow, 0 = last byte
//   - Value = byte0 + byte1*128 + byte2*128^2 + byte3*128^3
//   - Maximum 4 bytes (max value: 268,435,455 = 2^28 - 1)
func (r *PacketReader) ReadVariableByteInteger() (int, error) {
	if r.offset >= len(r.pkt) {
		return 0, errors.New("not enough data for variable byte integer")
	}

	multiplier := 1 // Multiplier for current byte position (1, 128, 128^2, 128^3)
	var value int   // Accumulated decoded value
	var pos int     // Current byte position (0-3)

	for pos < 4 && r.offset+pos < len(r.pkt) {
		encodedByte := r.pkt[r.offset+pos]
		// Extract 7-bit value (bits 0-6) and add to total with position-based multiplier
		value += int(encodedByte&0x7F) * multiplier
		multiplier *= 128 // Next byte is worth 128x more

		// Check continuation bit (bit 7): 0 means this is the last byte
		if (encodedByte & 0x80) == 0 {
			r.offset += pos + 1
			return value, nil
		}
		pos++
	}

	return 0, errors.New("variable byte integer encoding exceeds 4 bytes or incomplete")
}

// ReadString reads an MQTT string (2-byte length prefix + UTF-8 string).
func (r *PacketReader) ReadString() (string, error) {
	strLen, err := r.ReadUint16()
	if err != nil {
		return "", errors.New("not enough data for string length")
	}

	if r.offset+int(strLen) > len(r.pkt) {
		return "", errors.New("not enough data for string content")
	}

	str := string(r.pkt[r.offset : r.offset+int(strLen)])
	r.offset += int(strLen)

	return str, nil
}
