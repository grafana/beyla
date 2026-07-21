// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"log/slog"
	"strings"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

func HTTPRequestTraceToSpan(trace *HTTPRequestTrace) request.Span {
	// From C, assuming 0-ended strings
	method := cstr(trace.Method[:])
	path := cstr(trace.Path[:])
	pattern := cstr(trace.Pattern[:])
	scheme := cstr(trace.Scheme[:])
	origHost := cstr(trace.Host[:])

	var jsonRPC *request.JSONRPC
	var subType int
	if trace.IsJsonrpc {
		jsonRPC = &request.JSONRPC{
			Method:  pattern,
			Version: ebpfhttp.JSONRPCVersionV1,
		}
		pattern = path
		subType = request.HTTPSubtypeJSONRPC
	}

	if pattern != "" {
		pattern = stripPattern(pattern)
		if pattern == "/" {
			pattern = ""
		}
	}

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
		Type:           request.EventType(trace.Type),
		Method:         method,
		Path:           path,
		FullPath:       path,
		Route:          pattern,
		Peer:           peer,
		PeerPort:       int(trace.Conn.S_port),
		Host:           hostname,
		HostPort:       hostPort,
		ContentLength:  trace.ContentLength,
		ResponseLength: trace.ResponseLength,
		RequestStart:   int64(trace.GoStartMonotimeNs),
		Start:          int64(trace.StartMonotimeNs),
		End:            int64(trace.EndMonotimeNs),
		Status:         int(trace.Status),
		TraceID:        trace.Tp.TraceId,
		SpanID:         trace.Tp.SpanId,
		ParentSpanID:   trace.Tp.ParentId,
		TraceFlags:     trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		Statement: schemeHost,
		JSONRPC:   jsonRPC,
		SubType:   subType,
	}
}

func stripPattern(p string) string {
	if p != "" && p[0] == '/' {
		return p
	}

	for _, s := range []string{"GET ", "PUT ", "POST ", "PATCH ", "DELETE ", "OPTIONS ", "HEAD "} {
		if strings.HasPrefix(p, s) {
			return p[len(s):]
		}
	}

	return ""
}

func SQLRequestTraceToSpan(trace *SQLRequestTrace) request.Span {
	if request.EventType(trace.Type) != request.EventTypeSQLClient {
		slog.With("component", "goexec.spanner").Warn("unknown trace type", "type", trace.Type)
		return request.Span{}
	}

	// From C, assuming 0-ended strings
	sql := cstr(trace.Sql[:])

	method, tables := sqlprune.SQLParseOperationAndTables(sql)
	path := sqlprune.SQLTargetCollection(method, tables)

	peer := ""
	peerPort := 0
	host := ""
	hostPort := 0

	if trace.Conn.S_port != 0 || trace.Conn.D_port != 0 {
		peer, host = (*BPFConnInfo)(unsafe.Pointer(&trace.Conn)).reqHostInfo()
		peerPort = int(trace.Conn.S_port)
		hostPort = int(trace.Conn.D_port)
	}

	hostname := cstr(trace.Hostname[:])
	if idx := strings.LastIndex(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}

	subType := trace.SubType

	// if we didn't detect the type in Go, try heuristic detect
	if subType == uint8(request.DBGeneric) {
		switch hostPort {
		case 5432:
			subType = uint8(request.DBPostgres)
		case 3306:
			subType = uint8(request.DBMySQL)
		case 1434:
			subType = uint8(request.DBMSSQL)
		}
	}

	return request.Span{
		Type:          request.EventType(trace.Type),
		SubType:       int(subType),
		Method:        method,
		Path:          path,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          host,
		HostName:      hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        int(trace.Status),
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		Statement:      sql,
		DBQuerySummary: sqlprune.SQLQuerySummary(method, tables),
	}
}
