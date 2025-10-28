// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/net/http2"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/bhpack"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
)

type BPFHTTP2Info BpfHttp2GrpcRequestT

type Protocol uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	HTTP2 Protocol = iota + 1
	GRPC
)

const initialHeaderTableSize = 4096

type h2Connection struct {
	hdec     *bhpack.Decoder
	hdecRet  *bhpack.Decoder
	protocol Protocol
}

func byteFramer(data []uint8) *http2.Framer {
	buf := bytes.NewBuffer(data)
	fr := http2.NewFramer(buf, buf) // the write is same as read, but we never write

	return fr
}

// not all requests for a given stream specify the protocol, but one must
// we remember if we see grpc mentioned and tag the rest of the streams for
// a given connection as grpc. default assumes plain HTTP2
// this is why we need the h2c cache
func getOrInitH2Conn(activeGRPCConnections *lru.Cache[uint64, h2Connection], connID uint64) *h2Connection {
	v, ok := activeGRPCConnections.Get(connID)

	dynamicTableSize := initialHeaderTableSize
	if connID == 0 {
		dynamicTableSize = 0
	}

	if !ok {
		h := h2Connection{
			hdec:     bhpack.NewDecoder(uint32(dynamicTableSize), nil),
			hdecRet:  bhpack.NewDecoder(uint32(dynamicTableSize), nil),
			protocol: HTTP2,
		}
		activeGRPCConnections.Add(connID, h)
		v, ok = activeGRPCConnections.Get(connID)
		if !ok {
			return nil
		}
	}

	return &v
}

func protocolIsGRPC(activeGRPCConnections *lru.Cache[uint64, h2Connection], connID uint64) {
	h2c := getOrInitH2Conn(activeGRPCConnections, connID)
	if h2c != nil {
		h2c.protocol = GRPC
	}
}

var commonHDec = bhpack.NewDecoder(0, nil)

func knownFrameKeys(fr *http2.Framer, hf *http2.HeadersFrame) bool {
	known := false
	commonHDec.SetEmitFunc(func(hf bhpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method", ":path", "content-type", ":status", "grpc-status":
			known = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer commonHDec.SetEmitFunc(func(_ bhpack.HeaderField) {})
	defer commonHDec.Close()

	frag := hf.HeaderBlockFragment()
	for {
		if _, err := commonHDec.Write(frag); err != nil {
			break
		}
		if hf.HeadersEnded() {
			break
		}
		hff, err := fr.ReadFrame()
		if err != nil {
			break
		}
		cf, ok := hff.(*http2.ContinuationFrame)
		if !ok {
			break
		}
		frag = cf.HeaderBlockFragment()
	}

	return known
}

func readMetaFrame(parseContext *EBPFParseContext, connID uint64, fr *http2.Framer, hf *http2.HeadersFrame) (string, string, string, bool) {
	h2c := getOrInitH2Conn(parseContext.h2c, connID)

	ok := false
	method := ""
	path := ""
	contentType := ""

	if h2c == nil {
		return method, path, contentType, ok
	}

	h2c.hdec.SetEmitFunc(func(hf bhpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method":
			method = hf.Value
			ok = true
		case ":path":
			path = hf.Value
			ok = true
		case "content-type":
			contentType = strings.ToLower(hf.Value)
			if contentType == "application/grpc" {
				protocolIsGRPC(parseContext.h2c, connID)
			}
			ok = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdec.SetEmitFunc(func(_ bhpack.HeaderField) {})
	defer h2c.hdec.Close()

	frag := hf.HeaderBlockFragment()
	for {
		if _, err := h2c.hdec.Write(frag); err != nil {
			return method, path, contentType, ok
		}
		if hf.HeadersEnded() {
			break
		}
		hff, err := fr.ReadFrame()
		if err != nil {
			break
		}
		cf, ok := hff.(*http2.ContinuationFrame)
		if !ok {
			break
		}
		frag = cf.HeaderBlockFragment()
	}

	return method, path, contentType, ok
}

func http2grpcStatus(status int) int {
	if status < 100 {
		return status
	}
	if status < 400 {
		return 0
	}

	return 2 // Unknown
}

func readRetMetaFrame(parseContext *EBPFParseContext, connID uint64, fr *http2.Framer, hf *http2.HeadersFrame) (int, bool, bool) {
	h2c := getOrInitH2Conn(parseContext.h2c, connID)

	ok := false
	status := 0
	grpc := false

	if h2c == nil {
		return status, grpc, ok
	}

	h2c.hdecRet.SetEmitFunc(func(hf bhpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		// grpc requests may have :status and grpc-status. :status will be HTTP code.
		// we prefer the grpc one if it exists, it's always later since : tagged headers
		// end up first in the headers list.
		switch hfKey {
		case ":status":
			if !grpc { // only set the HTTP status if we didn't find grpc status
				status, _ = strconv.Atoi(hf.Value)
			}
			ok = true
		case "grpc-status":
			status, _ = strconv.Atoi(hf.Value)
			protocolIsGRPC(parseContext.h2c, connID)
			grpc = true
			ok = true
		case "grpc-message":
			if hf.Value != "" {
				if !grpc { // unset or we have the HTTP status
					status = 2
				}
			}
			protocolIsGRPC(parseContext.h2c, connID)
			grpc = true
			ok = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdecRet.SetEmitFunc(func(_ bhpack.HeaderField) {})
	defer h2c.hdecRet.Close()

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := h2c.hdecRet.Write(frag); err != nil {
			return status, grpc, ok
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return status, grpc, ok
		}
	}

	return status, grpc, ok
}

func http2InfoToSpan(info *BPFHTTP2Info, method, path, peer, host string, status int, protocol Protocol) request.Span {
	return request.Span{
		Type:          info.eventType(protocol),
		Method:        method,
		Path:          removeQuery(path),
		Peer:          peer,
		PeerPort:      int(info.ConnInfo.S_port),
		Host:          host,
		HostPort:      int(info.ConnInfo.D_port),
		ContentLength: int64(info.Len),
		RequestStart:  int64(info.StartMonotimeNs),
		Start:         int64(info.StartMonotimeNs),
		End:           int64(info.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.TraceID(info.Tp.TraceId),
		SpanID:        trace.SpanID(info.Tp.SpanId),
		ParentSpanID:  trace.SpanID(info.Tp.ParentId),
		TraceFlags:    info.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   info.Pid.HostPid,
			UserPID:   info.Pid.UserPid,
			Namespace: info.Pid.Ns,
		},
	}
}

// The eBPF kernel side gives us information only if the event type is server or client. We reuse what's
// done for HTTP 1.1. We figure out what the protocol is by looking at the response status, is it :grpc-status,
// or :status. Then we know what the protocol actually is.
func (event *BPFHTTP2Info) eventType(protocol Protocol) request.EventType {
	eventType := request.EventType(event.Type)

	switch protocol {
	case HTTP2:
		return eventType // just use HTTP as is, no special handling
	case GRPC:
		switch eventType {
		case request.EventTypeHTTP:
			return request.EventTypeGRPC
		case request.EventTypeHTTPClient:
			return request.EventTypeGRPCClient
		}
	}

	return 0
}

func readFrameHeader(buf []byte) (http2.FrameHeader, error) {
	if len(buf) < frameHeaderLen {
		return http2.FrameHeader{}, errors.New("EOF")
	}
	return http2.FrameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2.FrameType(buf[3]),
		Flags:    http2.Flags(buf[4]),
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
	}, nil
}

//nolint:cyclop
func http2FromBuffers(parseContext *EBPFParseContext, event *BPFHTTP2Info) (request.Span, bool, error) {
	bLen := len(event.Data)
	if event.Len < int32(bLen) {
		bLen = int(event.Len)
	}

	framer := byteFramer(event.Data[:bLen])
	retFramer := byteFramer(event.RetData[:])

	// We don't set the framer.ReadMetaHeaders function to hpack.NewDecoder because
	// the http2.MetaHeadersFrame code wants a full grpc buffer with all the fields,
	// and if it sees our partially captured eBPF buffers, it will not parse the frame
	// while returning a (nil, error) tuple. We read the meta frame ourselves as long as
	// we can and terminate without an error when things fail to decode because of
	// partial buffers.

	status := 0
	eventType := HTTP2
	connID := event.NewConnId

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			fail := true
			// We could have read incomplete buffer from eBPF, if the grpc request was
			// too large. In this case the frame will be with size bigger than our buffer.
			// We don't care about what's all in this request, we want to see if we can
			// find the method and path, so we attempt to adjust the frame size and re-read.
			if strings.Contains(err.Error(), "unexpected EOF") && bLen > frameHeaderLen {
				fh, err := readFrameHeader(event.Data[:bLen])
				if err == nil && fh.Length > uint32(bLen-frameHeaderLen) {
					newLen := min(
						// If we ever use more than 256 for the buffers we have to
						// change this to encode properly in more than 1 byte
						bLen-frameHeaderLen, 255)
					event.Data[0] = 0
					event.Data[1] = 0
					event.Data[2] = uint8(newLen)
					framer = byteFramer(event.Data[:bLen])

					f, err = framer.ReadFrame()
					if err == nil {
						fail = false
					}
				}
			}
			if fail {
				break
			}
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			rok := false
			method, path, contentType, ok := readMetaFrame(parseContext, connID, framer, ff)

			if path == "" {
				path = "*"
			}

			grpcInStatus := false

			for {
				retF, err := retFramer.ReadFrame()
				if err != nil {
					break
				}

				if ff, ok := retF.(*http2.HeadersFrame); ok {
					status, grpcInStatus, rok = readRetMetaFrame(parseContext, connID, retFramer, ff)
					break
				}
			}

			// We read nothing of value
			if !ok && !rok {
				return request.Span{}, true, nil
			}

			// if we don't have protocol, assume gRPC if it's not ssl. HTTP2 is almost always SSL.
			if eventType != GRPC && (grpcInStatus || contentType == "application/grpc" || (contentType == "" && event.Ssl == 0)) {
				eventType = GRPC
				status = http2grpcStatus(status)
			}

			peer := ""
			host := ""
			if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
				source, target := (*BPFConnInfo)(unsafe.Pointer(&event.ConnInfo)).reqHostInfo()
				host = target
				peer = source
			}

			return http2InfoToSpan(event, method, path, peer, host, status, eventType), false, nil
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func ReadHTTP2InfoIntoSpan(parseContext *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BPFHTTP2Info](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	return http2FromBuffers(parseContext, event)
}

type http2FrameType uint8

type frameHeader struct {
	Length   uint32
	Type     http2FrameType
	Flags    uint8
	Ignore   uint8
	StreamID uint32
}

const (
	FrameData         http2FrameType = 0x0
	FrameHeaders      http2FrameType = 0x1
	FramePriority     http2FrameType = 0x2
	FrameRSTStream    http2FrameType = 0x3
	FrameSettings     http2FrameType = 0x4
	FramePushPromise  http2FrameType = 0x5
	FramePing         http2FrameType = 0x6
	FrameGoAway       http2FrameType = 0x7
	FrameWindowUpdate http2FrameType = 0x8
	FrameContinuation http2FrameType = 0x9
)

const frameHeaderLen = 9

func readHTTP2Frame(buf []uint8, length int) (*frameHeader, bool) {
	if length < frameHeaderLen {
		return nil, false
	}

	frame := frameHeader{
		Length:   (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Type:     http2FrameType(buf[3]),
		Flags:    buf[4],
		StreamID: binary.BigEndian.Uint32(buf[5:]) & (1<<31 - 1),
	}

	if frame.Length == 0 || frame.Type > FrameContinuation {
		return nil, false
	}

	return &frame, true
}

func isHeadersFrame(frame *frameHeader) bool {
	return frame.Type == FrameHeaders && frame.StreamID != 0
}

func isInvalidFrame(frame *frameHeader) bool {
	return frame.Length == 0 && frame.Type == FrameData
}

func isLikelyHTTP2(data []uint8, eventLen int) bool {
	pos := 0
	l := min(eventLen, len(data))
	for range 8 {
		if pos > l-frameHeaderLen {
			break
		}

		fr, ok := readHTTP2Frame(data[pos:], l)
		if !ok {
			break
		}

		if isHeadersFrame(fr) {
			return true
		}

		if isInvalidFrame(fr) {
			break
		}

		if pos < (l - int(fr.Length+frameHeaderLen)) {
			pos += int(fr.Length + frameHeaderLen)
			continue
		}

		break
	}

	return false
}

func isHTTP2(data []uint8, eventLen int) bool {
	// Parsing HTTP2 frames with the Go HTTP2/gRPC parser is very expensive.
	// Therefore, we replicate some of our HTTP2 frame reader from eBPF here to
	// check if this payload even remotely looks like HTTP2/gRPC, e.g. we must
	// find a resonably looking HTTP "headers" frame.
	if !isLikelyHTTP2(data, eventLen) {
		return false
	}

	framer := byteFramer(data)

	for {
		f, err := framer.ReadFrame()
		if err != nil {
			break
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			return knownFrameKeys(framer, ff)
		}
	}

	return false
}
