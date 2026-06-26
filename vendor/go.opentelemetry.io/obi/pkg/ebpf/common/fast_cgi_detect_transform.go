// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
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
	queryStringKey          = "QUERY_STRING"
	responseError           = 7 // FCGI_STDERR
	responseStatusKey       = "Status: "
)

const (
	fcgiVersion1          = 1
	fcgiFrameTypeBeginReq = 1
	fcgiFrameTypeUnknown  = 11
	fcgiFrameTypeParams   = 4
)

var (
	errFastCGIPayloadTooShort  = errors.New("payload too short")
	errFastCGIHeaderReadFailed = errors.New("failed to read FastCGI header")
)

// fastCGIHeader represents the structure of a FastCGI header
type fastCGIHeader struct {
	Version       uint8  // Protocol version
	Type          uint8  // Record type
	RequestID     uint16 // Request ID (big-endian)
	ContentLength uint16 // Content length (big-endian)
	PaddingLength uint8  // Padding length
	Reserved      uint8  // Reserved (always 0)
}

// ReadFastCGIHeader reads a FastCGI header from an input stream
func readFastCGIHeader(b []byte) (*fastCGIHeader, error) {
	reader := bytes.NewReader(b)
	// FastCGI header is always 8 bytes
	headerBytes := make([]byte, fastCGIRequestHeaderLen)
	if _, err := io.ReadFull(reader, headerBytes); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}

	// Parse the header
	header := &fastCGIHeader{}
	buffer := bytes.NewReader(headerBytes)

	if err := binary.Read(buffer, binary.BigEndian, &header.Version); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}
	if err := binary.Read(buffer, binary.BigEndian, &header.Type); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}
	if err := binary.Read(buffer, binary.BigEndian, &header.RequestID); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}
	if err := binary.Read(buffer, binary.BigEndian, &header.ContentLength); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}
	if err := binary.Read(buffer, binary.BigEndian, &header.PaddingLength); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}
	if err := binary.Read(buffer, binary.BigEndian, &header.Reserved); err != nil {
		return nil, errFastCGIHeaderReadFailed
	}

	return header, nil
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
		hdr, err := readFastCGIHeader(hdrBytes)
		if err != nil {
			return nil, errFastCGIPayloadTooShort
		}

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

func detectFastCGI(b, rb *largebuf.LargeBuffer) (string, string, int) {
	raw, err := parseHeader(b)
	if err != nil {
		return "", "", -1
	}

	methodPos := bytes.Index(raw, []byte(requestMethodKey))
	if methodPos >= 0 {
		kv := parseCGITable(raw)

		method, ok := kv[requestMethodKey]
		if !ok {
			return "", "", -1
		}
		uri := kv[requestURIKey]
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
		Path:          removeQuery(uri),
		FullPath:      uri,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
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
