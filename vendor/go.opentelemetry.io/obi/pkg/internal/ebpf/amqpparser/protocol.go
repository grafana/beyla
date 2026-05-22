// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const protocolHeaderSize = 8

const (
	protocolIDOffset = len("AMQP")
	majorOffset      = protocolIDOffset + 1
	minorOffset      = majorOffset + 1
	revisionOffset   = minorOffset + 1
)

var amqpMagic = []byte("AMQP")

var amqpVersion = [3]byte{1, 0, 0}

type protocolID uint8

const (
	protocolIDAMQP    protocolID = 0
	protocolIDAMQPTLS protocolID = 2
	protocolIDSASL    protocolID = 3
)

type protocolHeader struct {
	ID       protocolID
	Major    uint8
	Minor    uint8
	Revision uint8
}

func startsWithMagic(r *largebuf.LargeBufferReader) bool {
	data, err := r.Peek(len(amqpMagic))
	return err == nil && bytes.Equal(data, amqpMagic)
}

// IsLikelyAMQP is an O(1) prefilter that reports whether the buffer behind r
// could plausibly start an AMQP 1.0 conversation. It accepts either the
// connection preamble ("AMQP" magic) or a structurally valid frame header.
// The full Parse should still be invoked to confirm - this only filters out
// obviously non-AMQP payloads cheaply. The reader's cursor is not advanced,
// so the caller can pass the same reader straight to Parse on success.
// https://docs.oasis-open.org/amqp/core/v1.0/csprd01/amqp-core-transport-v1.0-csprd01.html
func IsLikelyAMQP(r *largebuf.LargeBufferReader) bool {
	if r == nil {
		return false
	}
	remaining := r.Remaining()

	if remaining >= len(amqpMagic) {
		head, err := r.Peek(len(amqpMagic))
		if err == nil && bytes.Equal(head, amqpMagic) {
			return true
		}
	}

	if remaining < frameHeaderSize {
		return false
	}

	hdr, err := r.Peek(frameHeaderSize)
	if err != nil {
		return false
	}

	// Frame header: size(u32 BE) | doff(u8) | type(u8) | channel(u16).
	// type 0x00 (AMQP) or 0x01 (SASL) alone filters out ~99% of random bytes.
	size := binary.BigEndian.Uint32(hdr[0:4])
	if size < frameHeaderSize {
		return false
	}
	if hdr[4] < minDataOffsetWords {
		return false
	}
	ft := hdr[5]
	if ft != byte(frameTypeAMQP) && ft != byte(frameTypeSASL) {
		return false
	}

	// If this frame carries a performative (size > bodyOffset) and that byte
	// is in the captured buffer, it must begin with the described-type
	// constructor (0x00). Heartbeat / idle frames have size == bodyOffset and
	// no body at all (AMQP 1.0 2.4.5), so the byte at bodyOffset belongs to
	// the next frame and must not be validated.
	bodyOffset := int(hdr[4]) * dataOffsetUnit
	if int(size) > bodyOffset && bodyOffset < remaining {
		body, err := r.Peek(bodyOffset + 1)
		if err != nil {
			return false
		}
		if body[bodyOffset] != describedTypeConstructor {
			return false
		}
	}

	return true
}

// parseProtocolHeader validates and parses an AMQP 1.0 protocol header.
// Non-1.0 versions are rejected to avoid false positives on AMQP 0-9-1.
func parseProtocolHeader(r *largebuf.LargeBufferReader) (protocolHeader, error) {
	if r.Remaining() < protocolHeaderSize {
		return protocolHeader{}, errors.New("packet too short for AMQP protocol header")
	}

	data, err := r.ReadN(protocolHeaderSize)
	if err != nil {
		return protocolHeader{}, err
	}

	if !bytes.Equal(data[:len(amqpMagic)], amqpMagic) {
		return protocolHeader{}, errors.New("missing AMQP protocol magic")
	}

	h := protocolHeader{
		ID:       protocolID(data[protocolIDOffset]),
		Major:    data[majorOffset],
		Minor:    data[minorOffset],
		Revision: data[revisionOffset],
	}

	switch h.ID {
	case protocolIDAMQP, protocolIDAMQPTLS, protocolIDSASL:
	default:
		return protocolHeader{}, fmt.Errorf("invalid AMQP 1.0 protocol id %d", h.ID)
	}

	if h.Major != amqpVersion[0] || h.Minor != amqpVersion[1] || h.Revision != amqpVersion[2] {
		return protocolHeader{}, fmt.Errorf("unsupported AMQP protocol version %d.%d.%d", h.Major, h.Minor, h.Revision)
	}

	return h, nil
}
