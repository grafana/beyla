package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type BPFHTTP2Info bpfHttp2GrpcRequestT

func byteFramer(data []uint8) *http2.Framer {
	buf := bytes.NewBuffer(data)
	fr := http2.NewFramer(buf, buf) // the write is same as read, but we never write

	return fr
}

func readMetaFrame(fr *http2.Framer, hf *http2.HeadersFrame) (string, string) {
	method := ""
	path := ""

	hdec := hpack.NewDecoder(0, nil)
	hdec.SetMaxStringLength(4096)
	hdec.SetEmitFunc(func(hf hpack.HeaderField) {
		hfKey := strings.ToLower(hf.Name)
		switch hfKey {
		case ":method":
			method = hf.Value
		case ":path":
			path = hf.Value
		}
	})
	// Lose reference to MetaHeadersFrame:
	defer hdec.SetEmitFunc(func(hf hpack.HeaderField) {})

	for {
		frag := hf.HeaderBlockFragment()
		if _, err := hdec.Write(frag); err != nil {
			return method, path
		}

		if hf.HeadersEnded() {
			break
		}
		if _, err := fr.ReadFrame(); err != nil {
			return method, path
		}
	}

	return method, path
}

var genericServiceID = svc.ID{SDKLanguage: svc.InstrumentableGeneric}

func http2InfoToSpan(info *BPFHTTP2Info, method, path, peer, host string) request.Span {
	return request.Span{
		Type:          request.EventType(info.Type),
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
		Status:        1,
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
	// We don't set the framer.ReadMetaHeaders function to hpack.NewDecoder because
	// the http2.MetaHeadersFrame code wants a full grpc buffer with all the fields,
	// and if it sees our partially captured eBPF buffers, it will not parse the frame
	// while returning a (nil, error) tuple. We read the meta frame ourselves as long as
	// we can and terminate without an error when things fail to decode because of
	// partial buffers.

	f, _ := framer.ReadFrame()

	switch ff := f.(type) {
	case *http2.HeadersFrame:
		method, path := readMetaFrame(framer, ff)
		peer := ""
		host := ""
		if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
			source, target := event.hostInfo()
			host = target
			peer = source
		}

		return http2InfoToSpan(&event, method, path, peer, host), false, nil
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}
