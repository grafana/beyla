// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

type largeBufferKind uint8

// must match the table large_buf_kind in common.h
const (
	KindLayerWire largeBufferKind = 0
	KindLayerApp  largeBufferKind = 1
)

type largeBufferKey struct {
	traceID               [16]uint8
	packetType, direction uint8
	connInfo              BpfConnectionInfoT
	kind                  largeBufferKind
}

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
		kind:       largeBufferKind(event.Kind),
	}

	if parseCtx.protocolDebug {
		fmt.Printf(">>> LargeBufferAppend: (packet=%d direction=%d action=%d size=%d kind=%d)\n%s\n",
			event.PacketType, event.Direction, event.Action, event.Len, event.Kind,
			string(record.RawSample[hdrSize:hdrSize+event.Len]))
	}

	chunk := record.RawSample[hdrSize : hdrSize+event.Len]

	initFunc := func(b []byte) {
		lb := largebuf.NewLargeBuffer()
		lb.AppendChunk(b)
		parseCtx.largeBuffers.Add(key, lb)
	}

	switch event.Action {
	case largeBufferActionInit:
		initFunc(chunk)
	case largeBufferActionAppend:
		lb, ok := parseCtx.largeBuffers.Get(key)
		if !ok {
			initFunc(chunk)
		} else {
			lb.AppendChunk(chunk)
		}
	default:
		return request.Span{}, true, fmt.Errorf("invalid large buffer action: %d", event.Action)
	}

	return request.Span{}, true, nil
}

func extractLargeBuffer(
	parseCtx *EBPFParseContext,
	traceID [16]uint8,
	packetType, direction uint8,
	connInfo BpfConnectionInfoT,
	kind largeBufferKind,
) (*largebuf.LargeBuffer, bool) {
	// The kind field tells us if we want to extract HTTP or TCP buffers. In normal circumstances
	// there never would be any mixup, it's either TCP or HTTP. However, when decrypt SSL we could
	// see SSL packets on the same connection before we decrypt the first SSL packet. In that instance
	// we may get TCP (SSL junk) and HTTP large buffers on the same connection and we need to
	// be able to tell them apart. For the same reason, we tell apart the special TCP protocols from
	// the generic TCP protocol
	key := largeBufferKey{
		traceID:    traceID,
		packetType: packetType,
		direction:  direction,
		connInfo:   connInfo,
		kind:       kind,
	}

	lb, ok := parseCtx.largeBuffers.Get(key)
	if !ok {
		if parseCtx.protocolDebug {
			fmt.Printf("<<< LargeBufferExtract: not found! (packet=%d direction=%d kind=%d)\n", key.packetType, key.direction, int(key.kind))
		}
		return nil, false
	}

	if parseCtx.protocolDebug {
		fmt.Printf("<<< LargeBufferExtract: (packet=%d direction=%d kind=%d len=%d)\n%s\n",
			key.packetType, key.direction, int(key.kind), lb.Len(), lb.UnsafeView())
	}

	parseCtx.largeBuffers.Remove(key)

	return lb, true
}

func protocolToLargeBufferKind(protocolType uint8) largeBufferKind {
	switch protocolType {
	case ProtocolTypeKafka, ProtocolTypeMySQL, ProtocolTypePostgres, ProtocolTypeMSSQL, ProtocolTypeHTTP:
		return KindLayerApp
	}
	// No large buffers for MQTT the rest are generic TCP buffers
	return KindLayerWire
}

func extractTCPLargeBuffer(
	parseCtx *EBPFParseContext,
	traceID [16]uint8,
	packetType, direction uint8,
	connInfo BpfConnectionInfoT,
	protocolType uint8,
) (*largebuf.LargeBuffer, bool) {
	return extractLargeBuffer(parseCtx, traceID, packetType, direction, connInfo, protocolToLargeBufferKind(protocolType))
}
