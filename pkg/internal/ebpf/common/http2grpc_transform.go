package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	lru "github.com/hashicorp/golang-lru/v2"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"

	"github.com/grafana/beyla/pkg/internal/ebpf/bhpack"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

type BPFHTTP2Info bpfHttp2GrpcRequestT

type Protocol uint8

// The following consts need to coincide with some C identifiers:
// EVENT_HTTP_REQUEST, EVENT_GRPC_REQUEST, EVENT_HTTP_CLIENT, EVENT_GRPC_CLIENT, EVENT_SQL_CLIENT
const (
	HTTP2 Protocol = iota + 1
	GRPC
)

type h2Connection struct {
	hdec     *bhpack.Decoder
	hdecRet  *bhpack.Decoder
	protocol Protocol
}

// not all requests for a given stream specify the protocol, but one must
// we remember if we see grpc mentioned and tag the rest of the streams for
// a given connection as grpc. default assumes plain HTTP2
var activeGRPCConnections, _ = lru.New[BPFConnInfo, h2Connection](1024 * 10)

func byteFramer(data []uint8) *http2.Framer {
	buf := bytes.NewBuffer(data)
	fr := http2.NewFramer(buf, buf) // the write is same as read, but we never write

	return fr
}

func getOrInitH2Conn(conn *BPFConnInfo) *h2Connection {
	v, ok := activeGRPCConnections.Get(*conn)

	if !ok {
		h := h2Connection{
			hdec:     bhpack.NewDecoder(0, nil),
			hdecRet:  bhpack.NewDecoder(0, nil),
			protocol: HTTP2,
		}
		activeGRPCConnections.Add(*conn, h)
		v, ok = activeGRPCConnections.Get(*conn)
		if !ok {
			return nil
		}
	}

	return &v
}

func protocolIsGRPC(conn *BPFConnInfo) {
	h2c := getOrInitH2Conn(conn)
	if h2c != nil {
		h2c.protocol = GRPC
	}
}

func readMetaFrame(conn *BPFConnInfo, fr *http2.Framer, hf *http2.HeadersFrame) (string, string, string) {
	h2c := getOrInitH2Conn(conn)

	method := ""
	path := ""
	contentType := ""

	if h2c == nil {
		return method, path, contentType
	}

	h2c.hdec.SetEmitFunc(func(hf bhpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		case "content-type":
			contentType = strings.ToLower(hf.Value)
			if contentType == "application/grpc" {
				protocolIsGRPC(conn)
			}
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdec.SetEmitFunc(func(_ bhpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := h2c.hdec.Write(frag); err != nil {
			return method, path, contentType
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return method, path, contentType
		}
	}

	return method, path, contentType
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

func readRetMetaFrame(conn *BPFConnInfo, fr *http2.Framer, hf *http2.HeadersFrame) (int, bool) {
	h2c := getOrInitH2Conn(conn)

	status := 0
	grpc := false

	if h2c == nil {
		return status, grpc
	}

	h2c.hdecRet.SetEmitFunc(func(hf bhpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		// grpc requests may have :status and grpc-status. :status will be HTTP code.
		// we prefer the grpc one if it exists, it's always later since : tagged headers
		// end up first in the headers list.
		switch hfKey {
		case ":status":
			status, _ = strconv.Atoi(hf.Value)
		case "grpc-status":
			status, _ = strconv.Atoi(hf.Value)
			protocolIsGRPC(conn)
			grpc = true
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer h2c.hdecRet.SetEmitFunc(func(_ bhpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := h2c.hdecRet.Write(frag); err != nil {
			return status, grpc
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return status, grpc
		}
	}

	return status, grpc
}

var genericServiceID = svc.ID{SDKLanguage: svc.InstrumentableGeneric}

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
		ServiceID:     genericServiceID, // set generic service to be overwritten later by the PID filters
		TraceID:       trace.TraceID(info.Tp.TraceId),
		SpanID:        trace.SpanID(info.Tp.SpanId),
		ParentSpanID:  trace.SpanID(info.Tp.ParentId),
		Flags:         info.Tp.Flags,
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

func (event *BPFHTTP2Info) hostInfo() (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, event.ConnInfo.S_addr[:])
	copy(dst, event.ConnInfo.D_addr[:])

	return src.String(), dst.String()
}

// nolint:cyclop
func ReadHTTP2InfoIntoSpan(record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	var event BPFHTTP2Info

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

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

	for {
		f, err := framer.ReadFrame()

		if err != nil {
			break
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			method, path, contentType := readMetaFrame((*BPFConnInfo)(&event.ConnInfo), framer, ff)

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
					status, grpcInStatus = readRetMetaFrame((*BPFConnInfo)(&event.ConnInfo), retFramer, ff)
					break
				}
			}

			// if we don't have protocol, assume gRPC if it's not ssl. HTTP2 is almost always SSL.
			if eventType != GRPC && (grpcInStatus || contentType == "application/grpc" || (contentType == "" && event.Ssl == 0)) {
				eventType = GRPC
				status = http2grpcStatus(status)
			}

			peer := ""
			host := ""
			if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
				source, target := event.hostInfo()
				host = target
				peer = source
			}

			return http2InfoToSpan(&event, method, path, peer, host, status, eventType), false, nil
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
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

func readHTTP2Frame(buf []uint8, len int) (*frameHeader, bool) {
	if len < frameHeaderLen {
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
	l := eventLen
	if l > len(data) {
		l = len(data)
	}
	for i := 0; i < 8; i++ {
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

func isHTTP2(data []uint8, event *TCPRequestInfo) bool {
	// Parsing HTTP2 frames with the Go HTTP2/gRPC parser is very expensive.
	// Therefore, we replicate some of our HTTP2 frame reader from eBPF here to
	// check if this payload even remotely looks like HTTP2/gRPC, e.g. we must
	// find a resonably looking HTTP "headers" frame.
	if !isLikelyHTTP2(data, int(event.Len)) {
		return false
	}

	framer := byteFramer(data)

	for {
		f, err := framer.ReadFrame()

		if err != nil {
			break
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			method, path, _ := readMetaFrame((*BPFConnInfo)(&event.ConnInfo), framer, ff)
			return method != "" || path != ""
		}
	}

	return false
}
