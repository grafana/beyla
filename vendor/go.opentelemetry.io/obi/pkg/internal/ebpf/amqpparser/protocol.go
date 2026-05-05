// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"bytes"
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
