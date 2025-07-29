// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
)

type (
	largeBufferKey struct {
		traceID   [16]uint8
		spanID    [8]uint8
		direction uint8
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
		traceID:   event.Tp.TraceId,
		spanID:    event.Tp.SpanId,
		direction: event.Direction,
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
			return request.Span{}, true, errors.New("existing large buffer not found for append action")
		}
		lb.buf = append(lb.buf, record.RawSample[hdrSize:hdrSize+event.Len]...)
	default:
		return request.Span{}, true, fmt.Errorf("invalid large buffer action: %d", event.Action)
	}

	return request.Span{}, true, nil
}

func extractTCPLargeBuffer(parseCtx *EBPFParseContext, traceID [16]uint8, spanID [8]uint8, direction uint8) ([]byte, bool) {
	key := largeBufferKey{
		spanID:    spanID,
		traceID:   traceID,
		direction: direction,
	}

	if lb, ok := parseCtx.largeBuffers.Get(key); ok {
		parseCtx.largeBuffers.Remove(key)
		return lb.buf, true
	}

	return nil, false
}
