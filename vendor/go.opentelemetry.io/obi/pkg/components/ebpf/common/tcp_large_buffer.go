// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

type (
	largeBufferKey struct {
		traceID    [16]uint8
		spanID     [8]uint8
		packetType uint8
	}
	largeBuffer struct {
		buf []byte
	}
)

const (
	largeBufferActionInit = iota
	largeBufferActionAppend
)

func appendTCPLargeBuffer(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(TCPLargeBufferHeader{})) - uint32(unsafe.Sizeof(uintptr(0))) // Remove `buf` placeholder

	event, err := ReinterpretCast[TCPLargeBufferHeader](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	key := largeBufferKey{
		traceID:    event.Tp.TraceId,
		spanID:     event.Tp.SpanId,
		packetType: event.PacketType,
	}

	switch event.Action {
	case largeBufferActionInit:
		newBuffer := make([]byte, event.Len)
		copy(newBuffer, record.RawSample[hdrSize:])
		parseCtx.largeBuffers.Add(key, &largeBuffer{
			buf: newBuffer,
		})
	case largeBufferActionAppend:
		lb, ok := parseCtx.largeBuffers.Get(key)
		if !ok {
			return request.Span{}, true, nil
		}
		lb.buf = append(lb.buf, record.RawSample[hdrSize:hdrSize+event.Len]...)
	default:
		return request.Span{}, true, fmt.Errorf("invalid large buffer action: %d", event.Action)
	}

	return request.Span{}, true, nil
}

func extractTCPLargeBuffer(parseCtx *EBPFParseContext, traceID [16]uint8, spanID [8]uint8, packetType uint8) ([]byte, bool) {
	key := largeBufferKey{
		spanID:     spanID,
		traceID:    traceID,
		packetType: packetType,
	}

	if lb, ok := parseCtx.largeBuffers.Get(key); ok {
		parseCtx.largeBuffers.Remove(key)
		return lb.buf, true
	}

	return nil, false
}
