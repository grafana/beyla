package ebpfcommon

import (
	"bytes"
	"log/slog"
	"net"
	"strconv"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/sqlprune"
)

var log = slog.With("component", "goexec.spanner")

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	methodLen := bytes.IndexByte(trace.Method[:], 0)
	if methodLen < 0 {
		methodLen = len(trace.Method)
	}
	method := string(trace.Method[:methodLen])
	pathLen := bytes.IndexByte(trace.Path[:], 0)
	if pathLen < 0 {
		pathLen = len(trace.Path)
	}
	path := string(trace.Path[:pathLen])

	peer := ""
	hostname := ""
	hostPort := 0

	switch request.EventType(trace.Type) {
	case request.EventTypeHTTPClient, request.EventTypeHTTP:
		peer, _ = extractHostPort(trace.RemoteAddr[:])
		hostname, hostPort = extractHostPort(trace.Host[:])
	case request.EventTypeGRPC:
		hostPort = int(trace.HostPort)
		peer = extractIP(trace.RemoteAddr[:], int(trace.RemoteAddrLen))
		hostname = extractIP(trace.Host[:], int(trace.HostLen))
	case request.EventTypeGRPCClient:
		hostname, hostPort = extractHostPort(trace.Host[:])
	default:
		log.Warn("unknown trace type", "type", trace.Type)
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		Method:        method,
		Path:          path,
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: trace.ContentLength,
		RequestStart:  int64(trace.GoStartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		//ServiceID: serviceInfo(trace.Pid.HostPid),
	}
}

func SQLRequestTraceToSpan(trace *SQLRequestTrace) request.Span {
	if request.EventType(trace.Type) != request.EventTypeSQLClient {
		log.Warn("unknown trace type", "type", trace.Type)
		return request.Span{}
	}

	// From C, assuming 0-ended strings
	sqlLen := bytes.IndexByte(trace.Sql[:], 0)
	if sqlLen < 0 {
		sqlLen = len(trace.Sql)
	}
	sql := string(trace.Sql[:sqlLen])

	method, path := sqlprune.SQLParseOperationAndTable(sql)

	return request.Span{
		Type:          request.EventType(trace.Type),
		Method:        method,
		Path:          path,
		Peer:          "",
		Host:          "",
		HostPort:      0,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		//ServiceID: serviceInfo(trace.Pid.HostPid),
	}
}

func extractHostPort(b []uint8) (string, int) {
	addrLen := bytes.IndexByte(b, 0)
	if addrLen < 0 {
		addrLen = len(b)
	}

	peer := ""
	peerPort := 0

	if addrLen > 0 {
		addr := string(b[:addrLen])
		ip, port, err := net.SplitHostPort(addr)
		if err != nil {
			peer = addr
		} else {
			peer = ip
			peerPort, _ = strconv.Atoi(port)
		}
	}

	return peer, peerPort
}

func extractIP(b []uint8, size int) string {
	if size > len(b) {
		size = len(b)
	}
	return net.IP(b[:size]).String()
}
