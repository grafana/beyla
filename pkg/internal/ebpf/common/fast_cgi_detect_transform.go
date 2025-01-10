package ebpfcommon

import (
	"bytes"
	"strconv"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
)

const fastCGIRequestHeaderLen = 24
const requestMethodKey = "REQUEST_METHOD"
const requestURIKey = "REQUEST_URI"
const scriptNameKey = "SCRIPT_NAME"
const responseError = 7 // FCGI_STDERR
const responseStatusKey = "Status: "

func parseCGITable(b []byte) map[string]string {
	res := map[string]string{}

	for {
		key := ""
		val := ""
		if len(b) <= 2 { // key len + val len
			break
		}

		keyLen := int(b[0])
		valLen := int(b[1])

		if keyLen < 0 || valLen < 0 {
			break
		}

		b = b[2:]

		if keyLen > 0 && len(b) >= keyLen {
			key = string(b[:keyLen])
			b = b[keyLen:]
		}

		if valLen > 0 && len(b) >= valLen {
			val = string(b[:valLen])
			b = b[valLen:]
		}

		if key != "" {
			res[key] = val
		}
	}

	return res
}

func maybeFastCGI(b []byte) bool {
	if len(b) <= fastCGIRequestHeaderLen {
		return false
	}

	methodPos := bytes.Index(b, []byte(requestMethodKey))

	return methodPos >= 0
}

func detectFastCGI(b, rb []byte) (string, string, int) {
	b = b[fastCGIRequestHeaderLen:]

	methodPos := bytes.Index(b, []byte(requestMethodKey))
	if methodPos >= 0 {
		kv := parseCGITable(b)

		method, ok := kv[requestMethodKey]
		if !ok {
			return "", "", -1
		}
		uri, ok := kv[requestURIKey]
		if !ok {
			uri = kv[scriptNameKey]
		}

		// Translate the status code into HTTP, 200 OK, 500 ERR
		status := 200

		if len(rb) >= 2 {
			if rb[1] == responseError {
				status = 500
			}

			statusPos := bytes.Index(rb, []byte(responseStatusKey))
			if statusPos >= 0 {
				rb = rb[statusPos+len(responseStatusKey):]
				nextSpace := bytes.Index(rb, []byte(" "))
				if nextSpace > 0 {
					statusStr := string(rb[:nextSpace])
					if parsed, err := strconv.ParseInt(statusStr, 10, 32); err == nil {
						status = int(parsed)
					}
				}
			}
		}

		return method, uri, status
	}
	return "", "", -1
}

func TCPToFastCGIToSpan(trace *TCPRequestInfo, op, uri string, status int) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeHTTPClient
	if trace.Direction == 0 {
		reqType = request.EventTypeHTTP
	}

	return request.Span{
		Type:          reqType,
		Method:        op,
		Path:          uri,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.Len),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
