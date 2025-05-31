package ebpfcommon

import (
	"encoding/json"
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
	body := cstr(trace.Body[:])
	contentType := cstr(trace.ContentType[:])
	// fmt.Println("HTTPRequestTraceToSpan", body, contentType)

	isJSONRPC, jsonRPCReq := isJSONRPC2OverHTTP(body, contentType)
	if isJSONRPC {
		if jsonRPCReq != nil {
			method = jsonRPCReq.Method
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
		TraceID:        trace2.TraceID(trace.Tp.TraceId),
		SpanID:         trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:   trace2.SpanID(trace.Tp.ParentId),
		Flags:          trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		Statement: schemeHost,
	}
}

type JSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
}

// isJSONRPC2OverHTTP returns true and the parsed body if the request is a JSON-RPC 2.0 call over HTTP.
func isJSONRPC2OverHTTP(body, contentType string) (bool, *JSONRPCRequest) {
	ct := strings.ToLower(contentType)
	ct = strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]) // Remove parameters

	validTypes := []string{
		"application/json",
		"application/json-rpc",
		"application/jsonrequest",
		"application/json+rpc",
	}
	isJSONContentType := false
	for _, vt := range validTypes {
		if ct == vt {
			isJSONContentType = true
			break
		}
	}
	if !isJSONContentType {
		return false, nil
	}

	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "{") {
		return false, nil
	}

	var obj JSONRPCRequest
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return false, nil
	}

	// JSON-RPC 2.0: must have "jsonrpc":"2.0" and "method"
	if obj.JSONRPC != "2.0" {
		return false, nil
	}
	if obj.Method == "" {
		return false, nil
	}

	return true, &obj
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
