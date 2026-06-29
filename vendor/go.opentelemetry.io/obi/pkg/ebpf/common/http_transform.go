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
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx >= 0 {
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

	// Embedding detection uses hostname+path matching and must run before
	// header-based detectors (OpenAI, Anthropic, etc.) so that known
	// embedding-only providers are not misclassified when they return
	// OpenAI-compatible response headers.
	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Embedding.Enabled {
		span, ok := ebpfhttp.EmbeddingSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	// Retrieval detection runs alongside embedding: both are host-anchored
	// and target dedicated vector database endpoints that do not overlap
	// with LLM providers, so ordering between them does not matter.
	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Retrieval.Enabled {
		span, ok := ebpfhttp.RetrievalSpan(&httpSpan, req, resp)
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

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Gemini.Enabled {
		span, ok := ebpfhttp.GeminiSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Rerank.Enabled {
		span, ok := ebpfhttp.RerankSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Qwen.Enabled {
		span, ok := ebpfhttp.QwenSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Bedrock.Enabled {
		span, ok := ebpfhttp.BedrockSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	// Parse JSON-RPC once and reuse for both MCP and plain JSON-RPC
	// detection, since MCP is a protocol layer on top of JSON-RPC.
	if parseCtx != nil && (parseCtx.payloadExtraction.HTTP.GenAI.MCP.Enabled || parseCtx.payloadExtraction.HTTP.JSONRPC.Enabled) {
		if parsed := ebpfhttp.TryParseJSONRPC(req); parsed != nil {
			if parseCtx.payloadExtraction.HTTP.GenAI.MCP.Enabled {
				span, ok := ebpfhttp.MCPSpanFromParsed(&httpSpan, req, resp, parsed)
				if ok {
					return span
				}
			}
			if parseCtx.payloadExtraction.HTTP.JSONRPC.Enabled {
				return ebpfhttp.JSONRPCSpanFromParsed(&httpSpan, resp, parsed)
			}
		}
	}

	if parseCtx != nil && parseCtx.httpEnricher != nil {
		parseCtx.httpEnricher.Enrich(&httpSpan, req, resp)
	}

	return httpSpan
}

func ReadHTTPInfoIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BPFHTTPInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Generated by Go instrumentation
	if event.EventSource == GenericEventSourceTypeKProbes && !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
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
		b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, isClient), event.ConnInfo, ProtocolTypeHTTP)
		if ok {
			requestBuffer = b
		} else {
			slog.Debug("missing large buffer for HTTP request", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "packetType", packetTypeRequest)
			requestBuffer = largebuf.NewLargeBufferFrom(event.Buf[:])
		}

		b, ok = extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, isClient), event.ConnInfo, ProtocolTypeHTTP)
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

	// When the body is empty but Content-Length indicates data should be
	// present, the body bytes may be at a different offset in the raw
	// buffer (e.g. SSL connections where headers and body arrive in
	// separate writes that get interleaved). Scan the raw buffer for a
	// JSON body and replace req.Body so downstream detectors can parse it.
	//
	// We probe a single byte instead of ReadAll to avoid allocating and
	// copying the entire body on the happy path.
	if req.ContentLength > 0 {
		recoverRequestBody(req, requestBuffer)
	}

	return httpRequestResponseToSpan(parseCtx, event, req, resp), false, nil
}

func recoverRequestBody(req *http.Request, requestBuffer *largebuf.LargeBuffer) {
	var probe [1]byte
	n, err := req.Body.Read(probe[:])
	if n > 0 {
		// Body is present (happy path); prepend the consumed byte.
		req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(probe[:1]), req.Body))
		return
	}

	// Body is empty despite Content-Length > 0; attempt recovery
	// from the raw buffer.
	if recovered := recoverJSONBodyFromBuffer(requestBuffer); len(recovered) > 0 {
		if int64(len(recovered)) > req.ContentLength {
			recovered = recovered[:req.ContentLength]
		}
		req.Body = io.NopCloser(bytes.NewBuffer(recovered))
		return
	}

	if err != nil {
		req.Body = readErrorCloser{err: err}
	}
}

type readErrorCloser struct {
	err error
}

func (r readErrorCloser) Read([]byte) (int, error) {
	return 0, r.err
}

func (r readErrorCloser) Close() error {
	return nil
}

// recoverJSONBodyFromBuffer scans the raw request buffer for a JSON object
// that appears after the HTTP headers. This handles SSL connections where
// the body may be at an unexpected offset due to interleaved writes.
func recoverJSONBodyFromBuffer(buf *largebuf.LargeBuffer) []byte {
	raw := buf.UnsafeView()
	if len(raw) == 0 {
		return nil
	}

	// Find end of HTTP headers.
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return nil
	}
	bodyStart := headerEnd + 4

	// Scan forward from header end to find a JSON object or array.
	for i := bodyStart; i < len(raw); i++ {
		if raw[i] == '{' || raw[i] == '[' {
			return append([]byte(nil), raw[i:]...)
		}
	}
	return nil
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
		resp, err = http.ReadResponse(rd, req)
	}
	if err != nil {
		return resp, err
	}

	if isChunkedResponse(resp) {
		raw := responseBuffer.UnsafeView()
		if bodyStart := findBodyStart(raw); bodyStart >= 0 {
			decoded := dechunkBody(raw[bodyStart:])
			resp.Body = io.NopCloser(bytes.NewReader(decoded))
			resp.TransferEncoding = nil
			resp.ContentLength = int64(len(decoded))
			resp.Header.Del("Transfer-Encoding")
		}
	}

	return resp, nil
}

func isChunkedResponse(resp *http.Response) bool {
	for _, te := range resp.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			return true
		}
	}
	return false
}

func findBodyStart(raw []byte) int {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return -1
	}
	return idx + 4
}

// dechunkBody decodes HTTP chunked transfer encoding from raw bytes,
// tolerating truncation at any point. Returns all successfully decoded
// chunk payloads concatenated.
func dechunkBody(data []byte) []byte {
	var result []byte
	pos := 0
	for pos < len(data) {
		// Find the end of the chunk-size line.
		lineEnd := bytes.Index(data[pos:], []byte("\r\n"))
		if lineEnd < 0 {
			break
		}
		sizeLine := string(data[pos : pos+lineEnd])

		// Strip chunk extensions (e.g. ";ext=val").
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		sizeLine = strings.TrimSpace(sizeLine)
		if sizeLine == "" {
			break
		}

		chunkSize, err := strconv.ParseUint(sizeLine, 16, 64)
		if err != nil {
			break
		}
		if chunkSize == 0 {
			break
		}

		chunkStart := pos + lineEnd + 2 // skip past \r\n
		available := len(data) - chunkStart
		if chunkSize > uint64(available) {
			// Truncated chunk: take whatever is available.
			result = append(result, data[chunkStart:]...)
			break
		}

		chunkEnd := chunkStart + int(chunkSize)

		result = append(result, data[chunkStart:chunkEnd]...)

		// Skip past chunk data + trailing \r\n.
		pos = chunkEnd + 2
	}
	return result
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
