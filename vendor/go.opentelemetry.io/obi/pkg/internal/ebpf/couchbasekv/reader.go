// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv // import "go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PacketReader provides primitive binary reading operations for memcached packets.
// It tracks the current offset automatically.
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

// SetOffset sets the current position to a new offset.
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
		return fmt.Errorf("not enough data to skip %d bytes, remaining: %d", n, r.Remaining())
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
	value := binary.BigEndian.Uint16(r.pkt[r.offset:])
	r.offset += 2
	return value, nil
}

// ReadUint32 reads a big-endian 32-bit unsigned integer.
func (r *PacketReader) ReadUint32() (uint32, error) {
	if r.offset+4 > len(r.pkt) {
		return 0, errors.New("not enough data for uint32")
	}
	value := binary.BigEndian.Uint32(r.pkt[r.offset:])
	r.offset += 4
	return value, nil
}

// ReadUint64 reads a big-endian 64-bit unsigned integer.
func (r *PacketReader) ReadUint64() (uint64, error) {
	if r.offset+8 > len(r.pkt) {
		return 0, errors.New("not enough data for uint64")
	}
	value := binary.BigEndian.Uint64(r.pkt[r.offset:])
	r.offset += 8
	return value, nil
}

// ReadBytes reads n bytes and returns them as a slice.
func (r *PacketReader) ReadBytes(n int) ([]byte, error) {
	if r.offset+n > len(r.pkt) {
		return nil, fmt.Errorf("not enough data for %d bytes, remaining: %d", n, r.Remaining())
	}
	data := r.pkt[r.offset : r.offset+n]
	r.offset += n
	return data, nil
}

// ReadString reads n bytes and returns them as a string.
func (r *PacketReader) ReadString(n int) (string, error) {
	data, err := r.ReadBytes(n)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// PeekUint8 reads a single byte without advancing the offset.
func (r *PacketReader) PeekUint8() (uint8, error) {
	if r.offset >= len(r.pkt) {
		return 0, errors.New("not enough data for uint8")
	}
	return r.pkt[r.offset], nil
}

// ReadHeader reads a complete memcached binary protocol header.
func (r *PacketReader) ReadHeader() (*Header, error) {
	if r.Remaining() < HeaderLen {
		return nil, fmt.Errorf("not enough data for header: got %d bytes, need %d", r.Remaining(), HeaderLen)
	}

	header, err := ParseHeader(r.pkt[r.offset:])
	if err != nil {
		return nil, err
	}

	r.offset += HeaderLen
	return header, nil
}
