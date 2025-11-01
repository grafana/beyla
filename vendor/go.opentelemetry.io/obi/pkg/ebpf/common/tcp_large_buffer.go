// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
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

	if parseCtx.protocolDebug {
		fmt.Printf(">>> LargeBufferAppend: (packet=%d direction=%d action=%d)\n%s\n", event.PacketType, event.Direction, event.Action, string(record.RawSample[hdrSize:hdrSize+event.Len]))
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

	//nolint:gocritic
	if lb, ok := parseCtx.largeBuffers.Get(key); ok {
		if parseCtx.protocolDebug {
			fmt.Printf("<<< LargeBufferExtract: (packet=%d direction=%d)\n%s\n", key.packetType, key.direction, string(lb.buf))
		}
		parseCtx.largeBuffers.Remove(key)
		return lb.buf, true
	} else {
		if parseCtx.protocolDebug {
			fmt.Println("<<< LargeBufferExtract: not found!")
		}
	}

	return nil, false
}
