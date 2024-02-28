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
	"golang.org/x/net/http2/hpack"

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

var hdec = hpack.NewDecoder(0, nil)

// not all requests for a given stream specify the protocol, but one must
// we remember if we see grpc mentioned and tag the rest of the streams for
// a given connection as grpc. default assumes plain HTTP2
var activeGRPCConnections, _ = lru.New[BPFConnInfo, Protocol](1024)

func byteFramer(data []uint8) *http2.Framer {
	buf := bytes.NewBuffer(data)
	fr := http2.NewFramer(buf, buf) // the write is same as read, but we never write

	return fr
}

func defaultProtocol(conn *BPFConnInfo) Protocol {
	proto, ok := activeGRPCConnections.Get(*conn)
	if !ok {
		proto = HTTP2
	}

	return proto
}

func protocolIsGRPC(conn *BPFConnInfo) {
	activeGRPCConnections.Add(*conn, GRPC)
}

func readMetaFrame(conn *BPFConnInfo, fr *http2.Framer, hf *http2.HeadersFrame) (string, string, Protocol) {
	method := ""
	path := ""
	proto := defaultProtocol(conn)

	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		case "content-type":
			if strings.ToLower(hf.Value) == "application/grpc" {
				protocolIsGRPC(conn)
				proto = GRPC
			}
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return method, path, proto
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return method, path, proto
		}
	}

	return method, path, proto
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

func readRetMetaFrame(conn *BPFConnInfo, fr *http2.Framer, hf *http2.HeadersFrame) (int, Protocol) {
	status := 0
	proto := defaultProtocol(conn)

	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":status":
			status, _ = strconv.Atoi(hf.Value)
			proto = HTTP2
		case ":grpc-status":
			status, _ = strconv.Atoi(hf.Value)
			protocolIsGRPC(conn)
			proto = GRPC
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return status, proto
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return status, proto
		}
	}

	return status, proto
}

var genericServiceID = svc.ID{SDKLanguage: svc.InstrumentableGeneric}

func http2InfoToSpan(info *BPFHTTP2Info, method, path, peer, host string, status int, protocol Protocol) request.Span {
	return request.Span{
		Type:          info.eventType(protocol),
		ID:            0,
		Method:        method,
		Path:          removeQuery(path),
		Peer:          peer,
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

func ReadHTTP2InfoIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event BPFHTTP2Info

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	framer := byteFramer(event.Data[:])
	retFramer := byteFramer(event.RetData[:])
	// We don't set the framer.ReadMetaHeaders function to hpack.NewDecoder because
	// the http2.MetaHeadersFrame code wants a full grpc buffer with all the fields,
	// and if it sees our partially captured eBPF buffers, it will not parse the frame
	// while returning a (nil, error) tuple. We read the meta frame ourselves as long as
	// we can and terminate without an error when things fail to decode because of
	// partial buffers.

	retF, _ := retFramer.ReadFrame()

	status := 0
	eventType := HTTP2

	switch ff := retF.(type) {
	case *http2.HeadersFrame:
		status, eventType = readRetMetaFrame((*BPFConnInfo)(&event.ConnInfo), retFramer, ff)
	}

	f, _ := framer.ReadFrame()

	switch ff := f.(type) {
	case *http2.HeadersFrame:
		method, path, proto := readMetaFrame((*BPFConnInfo)(&event.ConnInfo), framer, ff)

		if eventType != GRPC && proto == GRPC {
			eventType = proto
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

	return request.Span{}, true, nil // ignore if we couldn't parse it
}
