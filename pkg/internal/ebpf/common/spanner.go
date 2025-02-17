package ebpfcommon

import (
	"log/slog"
	"strings"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/sqlprune"
)

var log = slog.With("component", "goexec.spanner")

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	method := cstr(trace.Method[:])
	path := cstr(trace.Path[:])
	scheme := cstr(trace.Scheme[:])
	origHost := cstr(trace.Host[:])

	peer := ""
	hostname := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()

		hostPort = int(trace.Conn.D_port)
	}

	schemeHost := ""
	if scheme != "" || origHost != "" {
		schemeHost = strings.Join([]string{scheme, origHost}, request.SchemeHostSeparator)
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		Method:        method,
		Path:          path,
		Peer:          peer,
		PeerPort:      int(trace.Conn.S_port),
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
		Statement: schemeHost,
	}
}

func SQLRequestTraceToSpan(trace *SQLRequestTrace) request.Span {
	if request.EventType(trace.Type) != request.EventTypeSQLClient {
		log.Warn("unknown trace type", "type", trace.Type)
		return request.Span{}
	}

	// From C, assuming 0-ended strings
	sql := cstr(trace.Sql[:])

	method, path := sqlprune.SQLParseOperationAndTable(sql)

	peer := ""
	peerPort := 0
	hostname := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()
		peerPort = int(trace.Conn.S_port)
		hostPort = int(trace.Conn.D_port)
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		Method:        method,
		Path:          path,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
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
		Statement: sql,
	}
}
