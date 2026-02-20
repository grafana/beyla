// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package couchbasekv // import "go.opentelemetry.io/obi/pkg/internal/ebpf/couchbasekv"

import (
	"encoding/binary"
	"fmt"
	"iter"
)

// Header is a view into a 24-byte memcached binary protocol header.
//
// The interpretation of bytes 2-3 differs between classic and flexible framing:
//   - Classic (magic 0x80/0x81): bytes 2-3 = key length (uint16, big endian)
//   - Flexible framing (magic 0x08/0x18): byte 2 = framing extras length (uint8),
//     byte 3 = key length (uint8)
//
// The interpretation of bytes 6-7 differs between request (VBucket ID) and
// response (Status code) packets.
type Header []byte

func (h Header) Magic() Magic { return Magic(h[0]) }

func (h Header) Opcode() Opcode { return Opcode(h[1]) }

// FramingExtrasLen returns the framing extras length.
// Only meaningful for flexible framing packets (magic 0x08/0x18); returns 0 for classic format.
func (h Header) FramingExtrasLen() uint8 {
	if h.Magic().IsAltFormat() {
		return h[2]
	}
	return 0
}

// KeyLen returns the key length.
// For flexible framing this is byte 3 (uint8 stored as uint16).
// For classic format this is bytes 2-3 (uint16 big endian).
func (h Header) KeyLen() uint16 {
	if h.Magic().IsAltFormat() {
		return uint16(h[3])
	}
	return binary.BigEndian.Uint16(h[2:4])
}

func (h Header) ExtrasLen() uint8 { return h[4] }

// Status returns bytes 6-7 as status code of the response; returns 0 for requests.
func (h Header) Status() Status {
	if h.IsResponse() {
		return Status(binary.BigEndian.Uint16(h[6:8]))
	}
	return 0
}

// BodyLen returns the total body length = framing extras + extras + key + value.
func (h Header) BodyLen() uint32 { return binary.BigEndian.Uint32(h[8:12]) }

// Opaque returns the opaque (correlation ID) field.
func (h Header) Opaque() uint32 { return binary.BigEndian.Uint32(h[12:16]) }

// TotalLen returns the total packet length (header + body).
func (h Header) TotalLen() int {
	return HeaderLen + int(h.BodyLen())
}

// ValueLen returns the length of the value portion of the body.
func (h Header) ValueLen() int {
	return int(h.BodyLen()) - int(h.FramingExtrasLen()) - int(h.ExtrasLen()) - int(h.KeyLen())
}

// IsRequest returns true if this header is for a request packet.
func (h Header) IsRequest() bool { return h.Magic().IsRequest() }

// IsResponse returns true if this header is for a response packet.
func (h Header) IsResponse() bool { return h.Magic().IsResponse() }

// ParseHeader validates and returns a view into a 24-byte memcached binary
// protocol header. No data is copied; the returned Header shares the
// underlying memory of pkt.
func ParseHeader(pkt []byte) (Header, error) {
	if len(pkt) < HeaderLen {
		return nil, fmt.Errorf("packet too short for header: got %d bytes, need %d", len(pkt), HeaderLen)
	}

	magic := Magic(pkt[0])
	if !magic.IsValid() {
		return nil, fmt.Errorf("invalid magic byte: 0x%02x", pkt[0])
	}

	h := Header(pkt[:HeaderLen])

	if err := validateHeader(h); err != nil {
		return nil, err
	}

	return h, nil
}

// Packet is a view into a memcached binary protocol packet buffer.
// If the packet data is truncated, as much as possible is accessible via the
// accessor methods and the Truncated method returns true.
type Packet []byte

// ParsePacket validates and returns a view into a memcached binary protocol packet
// The view is capped to exactly the packet's declared length (or all
// available bytes if the packet is truncated).
func ParsePacket(pkt []byte) (Packet, error) {
	h, err := ParseHeader(pkt)
	if err != nil {
		return nil, err
	}

	totalLen := h.TotalLen()
	if totalLen > len(pkt) {
		// Truncated: use all available data
		return pkt, nil
	}
	// Cap to exactly this packet's data
	return pkt[:totalLen], nil
}

// ParsePackets returns an iterator over pipelined memcached packets in a TCP
// segment. Iteration stops on error or when no more
// complete headers are available.
func ParsePackets(segment []byte) iter.Seq2[Packet, error] {
	return func(yield func(Packet, error) bool) {
		offset := 0
		for offset < len(segment) {
			remaining := segment[offset:]
			if len(remaining) < HeaderLen {
				return
			}

			pkt, err := ParsePacket(remaining)
			if err != nil {
				yield(nil, err)
				return
			}

			if !yield(pkt, nil) {
				return
			}

			offset += pkt.Header().TotalLen()
		}
	}
}

func (p Packet) Header() Header {
	return Header(p[:HeaderLen])
}

// Key returns the key bytes (view into original buffer).
func (p Packet) Key() []byte {
	start := p.extrasEnd()
	end := p.keyEnd()
	if start >= end {
		return nil
	}
	return p[start:end]
}

// Value returns the value bytes (view into original buffer).
func (p Packet) Value() []byte {
	start := p.keyEnd()
	end := p.valueEnd()
	if start >= end {
		return nil
	}
	return p[start:end]
}

// IsRequest returns true if this packet is a request.
func (p Packet) IsRequest() bool {
	return p.Header().IsRequest()
}

// IsResponse returns true if this packet is a response.
func (p Packet) IsResponse() bool {
	return p.Header().IsResponse()
}

// KeyString returns the key as a string.
func (p Packet) KeyString() string {
	return string(p.Key())
}

// ValueString returns the value as a string.
func (p Packet) ValueString() string {
	return string(p.Value())
}

func (p Packet) framingExtrasEnd() int {
	end := HeaderLen + int(p.Header().FramingExtrasLen())
	if end > len(p) {
		end = len(p)
	}
	return end
}

func (p Packet) extrasEnd() int {
	end := p.framingExtrasEnd() + int(p.Header().ExtrasLen())
	if end > len(p) {
		end = len(p)
	}
	return end
}

func (p Packet) keyEnd() int {
	end := p.extrasEnd() + int(p.Header().KeyLen())
	if end > len(p) {
		end = len(p)
	}
	return end
}

func (p Packet) valueEnd() int {
	end := p.keyEnd() + p.Header().ValueLen()
	if end > len(p) {
		end = len(p)
	}
	return end
}

// validateHeader checks for basic validity of the parsed header.
func validateHeader(h Header) error {
	minBodyLen := int(h.FramingExtrasLen()) + int(h.ExtrasLen()) + int(h.KeyLen())
	if int(h.BodyLen()) < minBodyLen {
		return fmt.Errorf("invalid body length: %d < framingExtras(%d) + extras(%d) + key(%d)",
			h.BodyLen(), h.FramingExtrasLen(), h.ExtrasLen(), h.KeyLen())
	}

	return nil
}
