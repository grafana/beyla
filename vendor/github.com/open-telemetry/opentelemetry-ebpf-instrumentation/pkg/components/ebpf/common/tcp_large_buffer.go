package ebpfcommon

import (
	"unsafe"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
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

func setTCPLargeBuffer(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := uint32(unsafe.Sizeof(TCPLargeBufferHeader{}))

	event, err := ReinterpretCast[TCPLargeBufferHeader](record.RawSample[:hdrSize])
	if err != nil {
		return request.Span{}, true, err
	}
	hdrSize -= uint32(unsafe.Sizeof(uintptr(0))) // Remove `buf` placeholder
	newBuffer := record.RawSample[hdrSize:]

	key := largeBufferKey{
		traceID:   event.Tp.TraceId,
		spanID:    event.Tp.SpanId,
		direction: event.Direction,
	}

	copiedBuffer := make([]byte, event.Len)
	copy(copiedBuffer, newBuffer)
	parseCtx.largeBuffers.Add(key, largeBuffer{
		buf: copiedBuffer,
	})

	return request.Span{}, true, nil
}

func getTCPLargeBuffer(parseCtx *EBPFParseContext, traceID [16]uint8, spanID [8]uint8, direction uint8) ([]byte, bool) {
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
