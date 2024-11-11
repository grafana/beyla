package ebpfcommon

import (
	"bytes"
	"debug/gosym"
	"fmt"
	"log/slog"
	"strings"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/sqlprune"
)

var log = slog.With("component", "goexec.spanner")

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace, filter ServiceFilter) request.Span {
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
	errMsgLen := bytes.IndexByte(trace.Error.ErrMsg[:], 0)
	if errMsgLen < 0 {
		errMsgLen = len(trace.Error.ErrMsg)
	}
	path := string(trace.Path[:pathLen])

	peer := ""
	hostname := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()

		hostPort = int(trace.Conn.D_port)
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
		ErrorMessage:    string(trace.Error.ErrMsg[:errMsgLen]),
		ErrorStacktrace: extractErrorStacktrace(trace, filter.GetSymTab(trace.Pid.UserPid)),
	}
}

func extractErrorStacktrace(trace *HTTPRequestTrace, symTab *gosym.Table) string {
	var stacktrace strings.Builder
	if symTab != nil && trace.Error.UstackSz > 0 {
		for _, pc := range trace.Error.Ustack {
			f := symTab.PCToFunc(pc)
			if f == nil {
				break
			}
			file, line, _ := symTab.PCToLine(pc)
			stacktrace.WriteString(fmt.Sprintf("%s\n", f.Name))
			stacktrace.WriteString(fmt.Sprintf("\t%s:%d\n", file, line))
		}
	}
	return stacktrace.String()
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
