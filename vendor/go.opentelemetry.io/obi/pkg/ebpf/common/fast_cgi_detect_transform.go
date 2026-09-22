// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	fastCGIRequestHeaderLen = 8
	requestMethodKey        = "REQUEST_METHOD"
	requestURIKey           = "REQUEST_URI"
	documentURIKey          = "DOCUMENT_URI"
	scriptNameKey           = "SCRIPT_NAME"
	queryStringKey          = "QUERY_STRING"
	requestSchemeKey        = "REQUEST_SCHEME"
	forwardedProtoKey       = "HTTP_X_FORWARDED_PROTO"
	httpsKey                = "HTTPS"
	responseError           = 7 // FCGI_STDERR
	responseStatusKey       = "Status: "
)

// fastCGIRequest is the request metadata the params table carries. The FastCGI
// hop itself describes none of it: the scheme and URI belong to the HTTP
// request the front end received, and are only knowable from these keys.
type fastCGIRequest struct {
	method string
	uri    string
	scheme string
	status int
}

const (
	fcgiVersion1          = 1
	fcgiFrameTypeBeginReq = 1
	fcgiFrameTypeUnknown  = 11
	fcgiFrameTypeParams   = 4
)

var errFastCGIPayloadTooShort = errors.New("payload too short")

// fastCGIHeader represents the structure of a FastCGI header
type fastCGIHeader struct {
	Version       uint8  // Protocol version
	Type          uint8  // Record type
	RequestID     uint16 // Request ID (big-endian)
	ContentLength uint16 // Content length (big-endian)
	PaddingLength uint8  // Padding length
	Reserved      uint8  // Reserved (always 0)
}

// readFastCGIHeader parses a FastCGI record header from the first 8 bytes of b.
func readFastCGIHeader(b []byte) *fastCGIHeader {
	return &fastCGIHeader{
		Version:       b[0],
		Type:          b[1],
		RequestID:     binary.BigEndian.Uint16(b[2:4]),
		ContentLength: binary.BigEndian.Uint16(b[4:6]),
		PaddingLength: b[6],
		Reserved:      b[7],
	}
}

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

func maybeFastCGI(b *largebuf.LargeBuffer) bool {
	if b.Len() <= fastCGIRequestHeaderLen {
		return false
	}
	// FastCGI 1.0: every record starts with version=1 and a record type in
	// 1..11. Cheap 2-byte check that filters ~99.98% of non-FastCGI payloads
	// before the more expensive REQUEST_METHOD substring scan.

	ver, err := b.U8At(0)

	if err != nil || ver != fcgiVersion1 {
		return false
	}

	frameType, err := b.U8At(1)

	if err != nil || frameType < fcgiFrameTypeBeginReq || frameType > fcgiFrameTypeUnknown {
		return false
	}

	return bytes.Contains(b.UnsafeView(), []byte(requestMethodKey))
}

func parseHeader(b *largebuf.LargeBuffer) ([]byte, error) {
	r := b.NewReader()
	for {
		if r.Remaining() < fastCGIRequestHeaderLen {
			return nil, errFastCGIPayloadTooShort
		}
		hdrBytes, err := r.ReadN(fastCGIRequestHeaderLen)
		if err != nil {
			return nil, errFastCGIPayloadTooShort
		}
		hdr := readFastCGIHeader(hdrBytes)

		if hdr.Type == fcgiFrameTypeParams {
			if r.Remaining() == 0 {
				return nil, errFastCGIPayloadTooShort
			}
			rest, _ := r.ReadN(r.Remaining())
			return rest, nil
		}
		payloadOffset := int(hdr.ContentLength) + int(hdr.PaddingLength)
		if err := r.Skip(payloadOffset); err != nil {
			return nil, errFastCGIPayloadTooShort
		}
	}
}

// cgiScheme reports the scheme of the original client request. Semconv asks
// for the client's scheme, so X-Forwarded-Proto wins: behind a TLS-terminating
// proxy REQUEST_SCHEME describes the hop into PHP-FPM and reads `http` for a
// request the client made over TLS. REQUEST_SCHEME carries the scheme directly
// otherwise; HTTPS is the older convention and is set to a truthy value only
// for TLS. None present means the front end did not say, and guessing would be
// wrong for any TLS-terminated site.
func cgiScheme(kv map[string]string) string {
	if scheme := forwardedProto(kv[forwardedProtoKey]); scheme != "" {
		return scheme
	}

	if scheme := kv[requestSchemeKey]; scheme != "" {
		return scheme
	}

	switch kv[httpsKey] {
	case "on", "1":
		return "https"
	}

	return ""
}

// forwardedProto reads the left-most entry of an X-Forwarded-Proto list, which
// is the scheme the client used. The header arrives from the wire, so anything
// outside the two schemes semconv defines is discarded rather than reported.
func forwardedProto(header string) string {
	proto, _, _ := strings.Cut(header, ",")
	switch proto = strings.ToLower(strings.TrimSpace(proto)); proto {
	case "http", "https":
		return proto
	}

	return ""
}

// cgiRequestURI prefers the front end's original request line. DOCUMENT_URI and
// SCRIPT_NAME are the rewritten and resolved forms, which still name the path
// when REQUEST_URI was truncated or is not configured.
func cgiRequestURI(kv map[string]string) string {
	for _, key := range []string{requestURIKey, documentURIKey, scriptNameKey} {
		if uri := kv[key]; uri != "" {
			return uri
		}
	}

	return ""
}

func detectFastCGI(b, rb *largebuf.LargeBuffer) (fastCGIRequest, bool) {
	raw, err := parseHeader(b)
	if err != nil {
		return fastCGIRequest{}, false
	}

	found := bytes.Contains(raw, []byte(requestMethodKey))
	if found {
		kv := parseCGITable(raw)

		method, ok := kv[requestMethodKey]
		if !ok {
			return fastCGIRequest{}, false
		}
		uri := cgiRequestURI(kv)
		if qs := kv[queryStringKey]; qs != "" && strings.IndexByte(uri, '?') < 0 {
			if uri == "" {
				uri = "/"
			}
			uri = uri + "?" + qs
		}

		// Translate the status code into HTTP, 200 OK, 500 ERR
		status := 200

		rbRaw := rb.UnsafeView()
		if len(rbRaw) >= 2 {
			if rbRaw[1] == responseError {
				status = 500
			}

			statusPos := bytes.Index(rbRaw, []byte(responseStatusKey))
			if statusPos >= 0 {
				rbRaw = rbRaw[statusPos+len(responseStatusKey):]
				nextSpace := bytes.Index(rbRaw, []byte(" "))
				if nextSpace > 0 {
					statusStr := string(rbRaw[:nextSpace])
					if parsed, err := strconv.ParseInt(statusStr, 10, 32); err == nil {
						status = int(parsed)
					}
				}
			}
		}

		return fastCGIRequest{
			method: method,
			uri:    uri,
			scheme: cgiScheme(kv),
			status: status,
		}, true
	}
	return fastCGIRequest{}, false
}

func TCPToFastCGIToSpan(trace *TCPRequestInfo, req fastCGIRequest) request.Span {
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

	schemeHost := ""
	if req.scheme != "" {
		schemeHost = req.scheme + request.SchemeHostSeparator
	}

	return request.Span{
		Type:          reqType,
		Method:        req.method,
		Path:          removeQuery(req.uri),
		FullPath:      req.uri,
		Statement:     schemeHost,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        req.status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
	}
}
