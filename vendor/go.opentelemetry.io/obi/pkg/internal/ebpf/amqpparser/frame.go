// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	frameHeaderSize = 8

	// dataOffsetUnit: per AMQP 1.0 the body offset is expressed in 4-byte words.
	dataOffsetUnit = 4

	// minDataOffsetWords: doff >= 2 ensures the body offset covers the 8-byte frame header
	minDataOffsetWords = 2

	describedTypeConstructor byte = 0x00

	formatCodeSmallULong byte = 0x53
	formatCodeULong      byte = 0x80

	// Described-type prefix sizes: 0x00 constructor + format code + (1|8)-byte value.
	smallULongDescriptorSize = 3
	uLongDescriptorSize      = 10

	frameTypeAMQP frameType = 0x00
	frameTypeSASL frameType = 0x01

	descriptorOpen        descriptor = 0x10
	descriptorBegin       descriptor = 0x11
	descriptorAttach      descriptor = 0x12
	descriptorFlow        descriptor = 0x13
	descriptorTransfer    descriptor = 0x14
	descriptorDisposition descriptor = 0x15
	descriptorDetach      descriptor = 0x16
	descriptorEnd         descriptor = 0x17
	descriptorClose       descriptor = 0x18

	descriptorSASLMechanisms descriptor = 0x40
	descriptorSASLInit       descriptor = 0x41
	descriptorSASLChallenge  descriptor = 0x42
	descriptorSASLResponse   descriptor = 0x43
	descriptorSASLOutcome    descriptor = 0x44
)

var (
	errIncompleteFrame   = errors.New("incomplete AMQP frame")
	errTooShort          = errors.New("packet too short")
	errInvalidFrameSize  = errors.New("invalid frame size")
	errInvalidDataOffset = errors.New("invalid AMQP frame data offset")
	errInvalidBodyOffset = errors.New("invalid AMQP frame body offset")
	errInvalidType       = errors.New("invalid AMQP frame type")
	errBodyTooShort      = errors.New("AMQP frame body too short")
	errNotDescribed      = errors.New("AMQP performative is not described")
	errTruncated         = errors.New("AMQP ulong descriptor truncated")
	errBadEncoding       = errors.New("unsupported AMQP descriptor encoding")
	errUnknownDescriptor = errors.New("unknown AMQP performative descriptor")
)

type frameType uint8

type descriptor uint64

type frameHeader struct {
	Size            uint32
	DataOffsetWords uint8
	Type            frameType
}

func (h frameHeader) bodyOffset() int {
	return int(h.DataOffsetWords) * dataOffsetUnit
}

// parseFrameHeader validates and parses the fixed 8-byte AMQP frame header.
func parseFrameHeader(r *largebuf.LargeBufferReader) (frameHeader, error) {
	remaining := r.Remaining()
	if remaining < frameHeaderSize {
		return frameHeader{}, errTooShort
	}

	size, err := r.ReadU32BE()
	if err != nil {
		return frameHeader{}, err
	}
	if size < frameHeaderSize {
		return frameHeader{}, errInvalidFrameSize
	}

	doff, err := r.ReadU8()
	if err != nil {
		return frameHeader{}, err
	}
	if doff < minDataOffsetWords {
		return frameHeader{}, errInvalidDataOffset
	}

	ft, err := r.ReadU8()
	if err != nil {
		return frameHeader{}, err
	}
	if err := r.Skip(2); err != nil {
		return frameHeader{}, err
	}

	h := frameHeader{
		Size:            size,
		DataOffsetWords: doff,
		Type:            frameType(ft),
	}

	if h.bodyOffset() > int(h.Size) {
		return frameHeader{}, errInvalidBodyOffset
	}

	switch h.Type {
	case frameTypeAMQP, frameTypeSASL:
	default:
		return frameHeader{}, errInvalidType
	}

	if int(size) > remaining {
		return h, errIncompleteFrame
	}

	return h, nil
}

// parsePerformativeDescriptor reads the described-type smallulong or ulong
// descriptor from a frame payload.
func parsePerformativeDescriptor(r *largebuf.LargeBufferReader, frameStart int, header frameHeader) (descriptor, bool, error) {
	bodyStart := header.bodyOffset()
	frameEnd := frameStart + int(header.Size)
	if err := skipToOffset(r, frameStart+bodyStart); err != nil {
		return 0, false, err
	}

	desc, found, err := parseDescriptor(r, header.Type, frameEnd-r.ReadOffset())
	if err != nil {
		return 0, false, err
	}
	if err := skipToOffset(r, frameEnd); err != nil {
		return 0, false, err
	}

	return desc, found, nil
}

// parseDescriptor attempts to decode a described-type ulong descriptor from the current read offset.
func parseDescriptor(r *largebuf.LargeBufferReader, ft frameType, bodyLen int) (descriptor, bool, error) {
	if bodyLen == 0 {
		// AMQP heartbeat: zero-length body.
		return 0, false, nil
	}
	if bodyLen < smallULongDescriptorSize {
		return 0, false, errBodyTooShort
	}

	constructor, err := r.ReadU8()
	if err != nil {
		return 0, false, err
	}
	if constructor != describedTypeConstructor {
		return 0, false, errNotDescribed
	}

	formatCode, err := r.ReadU8()
	if err != nil {
		return 0, false, err
	}

	var desc descriptor
	switch formatCode {
	case formatCodeSmallULong:
		value, err := r.ReadU8()
		if err != nil {
			return 0, false, err
		}
		desc = descriptor(value)
	case formatCodeULong:
		if bodyLen < uLongDescriptorSize {
			return 0, false, errTruncated
		}
		value, err := r.ReadU64BE()
		if err != nil {
			return 0, false, err
		}
		desc = descriptor(value)
	default:
		return 0, false, errBadEncoding
	}

	if !isKnownPerformativeDescriptor(ft, desc) {
		return 0, false, errUnknownDescriptor
	}

	return desc, true, nil
}

// isKnownPerformativeDescriptor reports whether descriptor is a standard AMQP 1.0
// performative for the provided frame type.
func isKnownPerformativeDescriptor(ft frameType, descriptor descriptor) bool {
	switch ft {
	case frameTypeAMQP:
		switch descriptor {
		case descriptorOpen,
			descriptorBegin,
			descriptorAttach,
			descriptorFlow,
			descriptorTransfer,
			descriptorDisposition,
			descriptorDetach,
			descriptorEnd,
			descriptorClose:
			return true
		}
	case frameTypeSASL:
		switch descriptor {
		case descriptorSASLMechanisms,
			descriptorSASLInit,
			descriptorSASLChallenge,
			descriptorSASLResponse,
			descriptorSASLOutcome:
			return true
		}
	}

	return false
}
