// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfhttp "go.opentelemetry.io/obi/pkg/ebpf/common/http"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx > 0 {
		return url[:idx]
	}
	return url
}

type HTTPInfo struct {
	BPFHTTPInfo
	Method     string
	URL        string
	Host       string
	Peer       string
	HeaderHost string
	Body       string
}

// misses serviceID
func httpInfoToSpanLegacy(info *HTTPInfo) request.Span {
	scheme := "http"
	if info.Ssl == 1 {
		scheme = "https"
	}

	return request.Span{
		Type:           request.EventType(info.Type),
		Method:         info.Method,
		Path:           removeQuery(info.URL),
		FullPath:       info.URL,
		Peer:           info.Peer,
		PeerPort:       int(info.ConnInfo.S_port),
		Host:           info.Host,
		HostPort:       int(info.ConnInfo.D_port),
		ContentLength:  int64(info.Len),
		ResponseLength: int64(info.RespLen),
		RequestStart:   int64(info.ReqMonotimeNs),
		Start:          int64(info.StartMonotimeNs),
		End:            int64(info.EndMonotimeNs),
		Status:         int(info.Status),
		TraceID:        info.Tp.TraceId,
		SpanID:         info.Tp.SpanId,
		ParentSpanID:   info.Tp.ParentId,
		TraceFlags:     info.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(info.Pid.HostPid),
			UserPID:   app.PID(info.Pid.UserPid),
			Namespace: info.Pid.Ns,
		},
		Statement: scheme + request.SchemeHostSeparator + info.HeaderHost,
	}
}

func httpRequestResponseToSpan(parseCtx *EBPFParseContext, event *BPFHTTPInfo, req *http.Request, resp *http.Response) request.Span {
	defer req.Body.Close()
	defer resp.Body.Close()

	peer, host := (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()

	scheme := req.URL.Scheme
	if scheme == "" {
		if event.Ssl == 1 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}

	// Make sure the content length is non-zero
	reqContentLen := req.ContentLength
	if reqContentLen <= 0 {
		reqContentLen = int64(event.Len)
	}

	// The response len can be -1 if we use chunked
	// responses
	respContentLen := resp.ContentLength
	if respContentLen <= 0 {
		respContentLen = int64(event.RespLen)
	}

	reqType := request.EventType(event.Type)
	headerHost := req.Host
	if headerHost == "" && reqType == request.EventTypeHTTPClient {
		headerHost, _ = httpHostFromBuf(event.Buf[:])
	}

	// FullPath matches net/url.URL.String() (full URL or request-target), not RequestURI().
	httpSpan := request.Span{
		Type:           reqType,
		Method:         req.Method,
		Path:           removeQuery(req.URL.String()),
		FullPath:       req.URL.String(),
		Peer:           peer,
		PeerPort:       int(event.ConnInfo.S_port),
		Host:           host,
		HostPort:       int(event.ConnInfo.D_port),
		ContentLength:  reqContentLen,
		ResponseLength: respContentLen,
		RequestStart:   int64(event.ReqMonotimeNs),
		Start:          int64(event.StartMonotimeNs),
		End:            int64(event.EndMonotimeNs),
		Status:         resp.StatusCode,
		TraceID:        event.Tp.TraceId,
		SpanID:         event.Tp.SpanId,
		ParentSpanID:   event.Tp.ParentId,
		TraceFlags:     event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.Pid.HostPid),
			UserPID:   app.PID(event.Pid.UserPid),
			Namespace: event.Pid.Ns,
		},
		Statement: scheme + request.SchemeHostSeparator + headerHost,
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.AWS.Enabled {
		span, ok := ebpfhttp.AWSS3Span(&httpSpan, req, resp)
		if ok {
			return span
		}

		span, ok = ebpfhttp.AWSSQSSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if !isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GraphQL.Enabled {
		span, ok := ebpfhttp.GraphQLSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.Elasticsearch.Enabled {
		span, ok := ebpfhttp.ElasticsearchSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.SQLPP.Enabled {
		span, ok := ebpfhttp.SQLPPSpan(&httpSpan, req, resp, parseCtx.payloadExtraction.HTTP.SQLPP.EndpointPatterns)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.OpenAI.Enabled {
		span, ok := ebpfhttp.OpenAISpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Anthropic.Enabled {
		span, ok := ebpfhttp.AnthropicSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if parseCtx != nil && parseCtx.payloadExtraction.HTTP.Enrichment.Enabled {
		ebpfhttp.EnrichHTTPSpan(&httpSpan, req, resp, parseCtx.payloadExtraction.HTTP.Enrichment)
	}

	return httpSpan
}

func ReadHTTPInfoIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BPFHTTPInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Generated by Go instrumentation
	if !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	return HTTPInfoEventToSpan(parseCtx, event)
}

func HTTPInfoEventToSpan(parseCtx *EBPFParseContext, event *BPFHTTPInfo) (request.Span, bool, error) {
	var (
		requestBuffer, responseBuffer *largebuf.LargeBuffer
		hasResponse                   bool
		isClient                      = isClientEvent(event.Type)
	)

	slog.Debug("Event", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "buf", event.Buf[:])

	if event.HasLargeBuffers == 1 {
		b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, isClient), event.ConnInfo)
		if ok {
			requestBuffer = b
		} else {
			slog.Debug("missing large buffer for HTTP request", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "packetType", packetTypeRequest)
			requestBuffer = largebuf.NewLargeBufferFrom(event.Buf[:])
		}

		b, ok = extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, isClient), event.ConnInfo)
		if ok {
			responseBuffer = b
			hasResponse = true
		} else {
			slog.Debug("missing large buffer for HTTP response", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "packetType", packetTypeResponse)
		}
	} else {
		requestBuffer = largebuf.NewLargeBufferFrom(event.Buf[:])
	}

	if parseCtx != nil && !parseCtx.payloadExtraction.Enabled() {
		// There's no need to parse HTTP headers/body,
		// create the span directly.
		return httpRequestToSpan(event, requestBuffer), false, nil
	}

	if !hasResponse {
		// Large buffers disabled
		return httpRequestToSpan(event, requestBuffer), false, nil
	}

	// http.ReadRequest requires a *bufio.Reader; that one allocation is unavoidable.
	reqReader := requestBuffer.NewReader()
	req, err := http.ReadRequest(bufio.NewReader(&reqReader))
	resp, err2 := httpSafeParseResponse(responseBuffer, req)
	if err != nil || err2 != nil {
		slog.Debug("error while parsing http request or response, falling back to manual HTTP info parsing", "reqErr", err, "respErr", err2)
		return httpRequestToSpan(event, requestBuffer), false, nil
	}

	return httpRequestResponseToSpan(parseCtx, event, req, resp), false, nil
}

// HTTP response buffers might have been sent incomplete, before the full body.
// Try to parse the original buffer first, if an EOF is encountered, append an empty
// body to the buffer and try again.
func httpSafeParseResponse(responseBuffer *largebuf.LargeBuffer, req *http.Request) (*http.Response, error) {
	r := responseBuffer.NewReader()
	rd := bufio.NewReader(&r)
	resp, err := http.ReadResponse(rd, req)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		// Append empty body terminator and retry, reusing the same reader (preserves scratch).
		responseBuffer.AppendChunk([]byte("\r\n\r\n"))
		r.Reset()
		rd.Reset(&r)
		return http.ReadResponse(rd, req)
	}
	return resp, err
}

func httpRequestToSpan(event *BPFHTTPInfo, requestBuffer *largebuf.LargeBuffer) request.Span {
	var (
		result     = HTTPInfo{BPFHTTPInfo: *event}
		bufHost    string
		bufPort    int
		parsedHost bool
	)

	raw := requestBuffer.UnsafeView()

	// When we can't find the connection info, we signal that through making the
	// source and destination ports equal to max short. E.g. async SSL
	if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
		source, target := (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()
		result.Host = target
		result.Peer = source
	} else {
		bufHost, bufPort = httpHostFromBuf(raw)
		parsedHost = true

		if bufPort >= 0 {
			result.Host = bufHost
			result.ConnInfo.D_port = uint16(bufPort)
		}
	}
	result.URL = httpURLFromBuf(raw)
	result.Method = httpMethodFromBuf(raw)

	if request.EventType(result.Type) == request.EventTypeHTTPClient && !parsedHost {
		bufHost, _ = httpHostFromBuf(raw)
	}

	result.HeaderHost = bufHost

	return httpInfoToSpanLegacy(&result)
}

func httpURLFromBuf(req []byte) string {
	if end := bytes.IndexByte(req, 0); end >= 0 {
		req = req[:end]
	}

	space := bytes.IndexByte(req, ' ')
	if space < 0 {
		return ""
	}

	req = req[space+1:]

	nextSpace := bytes.IndexAny(req, " \r\n")
	if nextSpace < 0 {
		return string(req)
	}

	return string(req[:nextSpace])
}

func httpMethodFromBuf(req []byte) string {
	method, _, found := bytes.Cut(req, []byte(" "))
	if !found {
		return ""
	}

	return string(method)
}

func httpHostFromBuf(req []byte) (string, int) {
	if end := bytes.IndexByte(req, 0); end >= 0 {
		req = req[:end]
	}

	idx := bytes.Index(req, []byte("Host: "))
	if idx < 0 {
		return "", -1
	}

	req = req[idx+len("Host: "):]

	// only parse full host information, partial may
	// get the wrong name or wrong port
	hostPort, _, found := bytes.Cut(req, []byte("\r"))
	if !found {
		return "", -1
	}
	host, portStr, err := net.SplitHostPort(string(hostPort))
	if err != nil {
		return string(hostPort), -1
	}

	port, _ := strconv.Atoi(portStr)

	return host, port
}
