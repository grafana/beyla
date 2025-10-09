// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type (
	largeBufferKey struct {
		traceID               [16]uint8
		packetType, direction uint8
		connInfo              BpfConnectionInfoT
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
		packetType: event.PacketType,
		direction:  event.Direction,
		connInfo:   event.ConnInfo,
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

func extractTCPLargeBuffer(parseCtx *EBPFParseContext, traceID [16]uint8, packetType, direction uint8, connInfo BpfConnectionInfoT) ([]byte, bool) {
	key := largeBufferKey{
		traceID:    traceID,
		packetType: packetType,
		direction:  direction,
		connInfo:   connInfo,
	}

	if lb, ok := parseCtx.largeBuffers.Get(key); ok {
		parseCtx.largeBuffers.Remove(key)
		return lb.buf, true
	}

	return nil, false
}
