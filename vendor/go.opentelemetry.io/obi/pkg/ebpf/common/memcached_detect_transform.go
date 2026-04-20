// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"strconv"
	"strings"
	"unsafe"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	memcachedDelim       = "\r\n"
	minMemcachedFrameLen = 3
)

var (
	memcachedDelimBytes = []byte(memcachedDelim)
	memcachedCommands   = map[string]struct{}{
		"get": {}, "gets": {}, "gat": {}, "gats": {}, "set": {}, "add": {}, "replace": {}, "append": {}, "prepend": {}, "cas": {},
		"delete": {}, "incr": {}, "decr": {}, "touch": {}, "flush_all": {}, "stats": {}, "version": {},
	}
	memcachedResponses = map[string]struct{}{
		"VALUE": {}, "END": {}, "STORED": {}, "NOT_STORED": {}, "EXISTS": {}, "NOT_FOUND": {}, "DELETED": {}, "TOUCHED": {},
		"OK": {}, "ERROR": {}, "CLIENT_ERROR": {}, "SERVER_ERROR": {}, "VERSION": {}, "STAT": {},
	}
)

type memcachedRequestOp struct {
	Op      string
	Key     string
	Noreply bool
}

type memcachedParseResult struct {
	Ops        []memcachedRequestOp
	IsResponse bool
}

func isMemcachedBuf(buf *largebuf.LargeBuffer) bool {
	if buf.Len() < minMemcachedFrameLen {
		return false
	}

	line, ok := memcachedFirstLineFromBuffer(buf)
	if !ok {
		return false
	}
	if isMemcachedNumericLine(line) {
		return true
	}

	token := memcachedToken(line)
	if len(token) == 0 {
		return false
	}

	return isMemcachedToken(token, memcachedCommands) || isMemcachedToken(token, memcachedResponses)
}

func isMemcached(req, resp *largebuf.LargeBuffer) bool {
	if !isMemcachedBuf(req) || !isMemcachedBuf(resp) {
		return false
	}
	requestReader := req.NewReader()
	if parsed, ok := parseMemcachedRequests(&requestReader); ok && !parsed.IsResponse && len(parsed.Ops) > 0 {
		responseReader := resp.NewReader()
		parsedResp, ok := parseMemcachedRequests(&responseReader)
		return ok && parsedResp.IsResponse
	}
	if resp.Len() == 0 {
		return false
	}
	responseReader := resp.NewReader()
	parsed, ok := parseMemcachedRequests(&responseReader)
	return ok && !parsed.IsResponse && len(parsed.Ops) > 0
}

// ProcessPossibleMemcachedEvent converts a confirmed memcached TCP exchange into a memcached span.
// It also emits extra spans for leading noreply operations recovered from combined requests.
func ProcessPossibleMemcachedEvent(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	requestReader := requestBuffer.NewReader()
	if parsed, ok := parseMemcachedRequests(&requestReader); ok && !parsed.IsResponse && len(parsed.Ops) > 0 {
		responseReader := responseBuffer.NewReader()
		parsedResp, ok := parseMemcachedRequests(&responseReader)
		if !ok || !parsedResp.IsResponse {
			return request.Span{}, errFallback
		}

		// Leading noreply operations must be emitted before the final reply-backed command.
		leading, replyOp, ok := memcachedReplyBackedOps(parsed.Ops)
		if !ok {
			return request.Span{}, errIgnore
		}

		emitMemcachedNoreplySpans(parseCtx, event, leading)

		memcachedErr, status := memcachedStatus(responseBuffer)
		return TCPToMemcachedToSpan(event, replyOp.Op, replyOp.Key, status, memcachedErr), nil
	}

	if responseBuffer.Len() == 0 {
		return request.Span{}, errFallback
	}

	responseReader := responseBuffer.NewReader()
	parsed, ok := parseMemcachedRequests(&responseReader)
	if !ok || parsed.IsResponse || len(parsed.Ops) == 0 {
		return request.Span{}, errFallback
	}

	leading, replyOp, ok := memcachedReplyBackedOps(parsed.Ops)
	if !ok {
		return request.Span{}, errIgnore
	}

	// Reversed buffers can happen when the TCP event is captured mid-exchange.
	reverseTCPEvent(event)
	emitMemcachedNoreplySpans(parseCtx, event, leading)

	memcachedErr, status := memcachedStatus(requestBuffer)
	return TCPToMemcachedToSpan(event, replyOp.Op, replyOp.Key, status, memcachedErr), nil
}

// parseMemcachedExplicitNoreply validates request-only memcached traffic flushed on close.
// In the ASCII protocol, some commands accept a trailing "noreply" modifier, which tells
// memcached not to send any response at all.
func parseMemcachedExplicitNoreply(r *largebuf.LargeBufferReader) ([]memcachedRequestOp, bool) {
	parsed, ok := parseMemcachedRequests(r)
	if !ok || parsed.IsResponse || len(parsed.Ops) == 0 {
		return nil, false
	}

	for _, op := range parsed.Ops {
		if !op.Noreply || !memcachedCommandSupportsNoreply(op.Op) {
			return nil, false
		}
	}

	return parsed.Ops, true
}

func memcachedStatus(buf *largebuf.LargeBuffer) (request.DBError, int) {
	if buf.Len() == 0 {
		return request.DBError{}, 0
	}

	line, ok := memcachedFirstLineFromBuffer(buf)
	if !ok || isMemcachedNumericLine(line) {
		return request.DBError{}, 0
	}

	token := memcachedToken(line)
	switch string(token) {
	case "ERROR", "CLIENT_ERROR", "SERVER_ERROR":
		return request.DBError{
			ErrorCode:   string(token),
			Description: string(bytes.TrimSpace(line)),
		}, 1
	default:
		return request.DBError{}, 0
	}
}

func TCPToMemcachedToSpan(trace *TCPRequestInfo, op, key string, status int, dbError request.DBError) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeMemcachedClient
	if trace.Direction == 0 {
		reqType = request.EventTypeMemcachedServer
	}

	return request.Span{
		Type:          reqType,
		Method:        op,
		Path:          key,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
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
		DBError: dbError,
	}
}

// memcachedNoreplySpan builds a request-only span for commands that were sent with the
// ASCII protocol's "noreply" modifier, for example "set key 0 300 5 noreply\r\nvalue\r\n".
func memcachedNoreplySpan(tcpTrace *TCPRequestInfo, op, key string) request.Span {
	span := TCPToMemcachedToSpan(tcpTrace, op, key, 0, request.DBError{})
	span.End = span.Start
	span.SpanID = trace.SpanID{}
	return span
}

// emitMemcachedNoreplySpans forwards extra spans recovered from a combined or request-only event.
func emitMemcachedNoreplySpans(parseCtx *EBPFParseContext, trace *TCPRequestInfo, ops []memcachedRequestOp) {
	if len(ops) == 0 {
		return
	}

	spans := make([]request.Span, 0, len(ops))
	for _, op := range ops {
		spans = append(spans, memcachedNoreplySpan(trace, op.Op, op.Key))
	}

	parseCtx.emitExtraSpans(spans...)
}

func parseMemcachedRequests(r *largebuf.LargeBufferReader) (memcachedParseResult, bool) {
	if isMemcachedResponseReader(r) {
		return memcachedParseResult{IsResponse: true}, true
	}

	ops := make([]memcachedRequestOp, 0, 1)
	for r.Remaining() > 0 {
		// Walk the full buffer so a leading noreply command does not hide the later reply-backed command.
		op, ok := parseMemcachedRequestOperation(r)
		if !ok {
			return memcachedParseResult{}, false
		}

		ops = append(ops, op)
	}

	return memcachedParseResult{Ops: ops, IsResponse: false}, true
}

func isMemcachedResponseReader(r *largebuf.LargeBufferReader) bool {
	line, ok := memcachedFirstLineFromReader(r)
	if !ok {
		return false
	}
	if isMemcachedNumericLine(line) {
		return true
	}

	token := memcachedToken(line)
	return len(token) > 0 && isMemcachedToken(token, memcachedResponses)
}

func parseMemcachedRequestOperation(r *largebuf.LargeBufferReader) (memcachedRequestOp, bool) {
	line, ok := memcachedReadLineFromReader(r)
	if !ok {
		return memcachedRequestOp{}, false
	}

	fields := bytes.Fields(line)
	if len(fields) == 0 {
		return memcachedRequestOp{}, false
	}

	token := fields[0]
	if isMemcachedToken(token, memcachedResponses) || isMemcachedNumericLine(line) {
		return memcachedRequestOp{}, false
	}
	if !isMemcachedToken(token, memcachedCommands) {
		return memcachedRequestOp{}, false
	}

	op := memcachedNormalizeCommand(string(token))
	noreply := memcachedFieldsHaveNoreply(fields)
	if noreply && !memcachedCommandSupportsNoreply(op) {
		return memcachedRequestOp{}, false
	}
	if !memcachedValidRequestFields(fields, op, noreply) {
		return memcachedRequestOp{}, false
	}

	if memcachedCommandHasPayload(op) && !memcachedConsumeStoragePayload(r, fields, op) {
		return memcachedRequestOp{}, false
	}

	opInfo := memcachedRequestOp{
		Op:      op,
		Noreply: noreply,
	}
	if keyField := memcachedCommandKeyField(op); keyField > 0 {
		opInfo.Key = string(fields[keyField])
	}

	return opInfo, true
}

func memcachedNormalizeCommand(token string) string {
	op := strings.ToUpper(token)
	if op == "GETS" { // GETS is a variant of GET that only differs in the response.
		return "GET"
	}
	if op == "GATS" { // GATS is the CAS-aware variant of GAT.
		return "GAT"
	}

	return op
}

func memcachedConsumeStoragePayload(r *largebuf.LargeBufferReader, fields [][]byte, op string) bool {
	bytesField, ok := memcachedCommandBytesField(fields, op)
	if !ok {
		return false
	}

	payloadLen := bytesField + len(memcachedDelimBytes)
	payload, err := r.Peek(payloadLen)
	if err != nil {
		return false
	}
	if !bytes.Equal(payload[bytesField:payloadLen], memcachedDelimBytes) {
		return false
	}

	return r.Skip(payloadLen) == nil
}

func memcachedReadLineFromReader(r *largebuf.LargeBufferReader) ([]byte, bool) {
	line, ok := memcachedFirstLineFromReader(r)
	if !ok {
		return nil, false
	}

	line, err := r.ReadN(len(line))
	if err != nil {
		return nil, false
	}

	if err := r.Skip(len(memcachedDelimBytes)); err != nil {
		return nil, false
	}

	return line, true
}

func memcachedFieldsHaveNoreply(fields [][]byte) bool {
	if len(fields) == 0 {
		return false
	}

	return bytes.Equal(fields[len(fields)-1], []byte("noreply"))
}

// memcachedCommandHasPayload identifies commands whose request line is followed by a data block.
func memcachedCommandHasPayload(op string) bool {
	switch op {
	case "SET", "ADD", "REPLACE", "APPEND", "PREPEND", "CAS":
		return true
	default:
		return false
	}
}

// memcachedCommandSupportsNoreply identifies commands that accept the noreply modifier.
func memcachedCommandSupportsNoreply(op string) bool {
	switch op {
	case "SET", "ADD", "REPLACE", "APPEND", "PREPEND", "CAS", "DELETE", "INCR", "DECR", "TOUCH", "FLUSH_ALL":
		return true
	default:
		return false
	}
}

// memcachedCommandBytesField extracts the payload byte-count from a storage command line.
// The size is always the fifth field in the ASCII storage format:
//
//	set <key> <flags> <exptime> <bytes> [noreply]
//
// CAS has one extra token after <bytes>:
//
//	cas <key> <flags> <exptime> <bytes> <cas unique> [noreply]
func memcachedCommandBytesField(fields [][]byte, op string) (int, bool) {
	const (
		minStorageFields = 5
		casFields        = 6
	)

	minFields := minStorageFields
	if op == "CAS" {
		minFields = casFields
	}
	if len(fields) < minFields {
		return 0, false
	}

	size, err := strconv.Atoi(string(fields[4]))
	if err != nil || size < 0 {
		return 0, false
	}

	return size, true
}

// memcachedReplyBackedOps splits a combined request into the earlier "noreply"
// commands and the last command that matches the response in this TCP event.
// Example: "set ... noreply" followed by "get ..." becomes leading [SET] and GET.
func memcachedReplyBackedOps(ops []memcachedRequestOp) ([]memcachedRequestOp, memcachedRequestOp, bool) {
	if len(ops) == 0 {
		return nil, memcachedRequestOp{}, false
	}

	last := ops[len(ops)-1]
	if last.Noreply {
		return nil, memcachedRequestOp{}, false
	}
	for _, op := range ops[:len(ops)-1] {
		if !op.Noreply {
			return nil, memcachedRequestOp{}, false
		}
	}

	return ops[:len(ops)-1], last, true
}

func memcachedFirstLineFromBuffer(buf *largebuf.LargeBuffer) ([]byte, bool) {
	if buf.Len() < minMemcachedFrameLen {
		return nil, false
	}

	crPos := buf.IndexByteAt(0, '\r')
	if crPos <= 0 || crPos+1 >= buf.Len() {
		return nil, false
	}

	lf, err := buf.U8At(crPos + 1)
	if err != nil || lf != '\n' {
		return nil, false
	}

	line, err := buf.UnsafeViewAt(0, crPos)
	return line, err == nil
}

func memcachedFirstLineFromReader(r *largebuf.LargeBufferReader) ([]byte, bool) {
	if r.Remaining() < minMemcachedFrameLen {
		return nil, false
	}

	crPos := r.IndexByte('\r')
	if crPos <= 0 || crPos+1 >= r.Remaining() {
		return nil, false
	}

	line, err := r.Peek(crPos + len(memcachedDelimBytes))
	if err != nil || line[crPos+1] != '\n' {
		return nil, false
	}

	return line[:crPos], true
}

func memcachedToken(line []byte) []byte {
	if idx := bytes.IndexByte(line, ' '); idx >= 0 {
		return line[:idx]
	}

	return line
}

// isMemcachedNumericLine recognizes numeric response lines used by incr/decr, for example "42\r\n".
func isMemcachedNumericLine(line []byte) bool {
	if len(line) == 0 {
		return false
	}

	for _, b := range line {
		if b < '0' || b > '9' {
			return false
		}
	}

	return true
}

func isMemcachedToken(token []byte, allowed map[string]struct{}) bool {
	_, ok := allowed[string(token)]
	return ok
}

// memcachedCommandKeyField returns the index of the key field for a given memcached command.
func memcachedCommandKeyField(op string) int {
	switch op {
	case "GET", "SET", "ADD", "REPLACE", "APPEND", "PREPEND", "CAS", "DELETE", "INCR", "DECR", "TOUCH":
		return 1
	case "GAT":
		return 2
	default:
		return -1
	}
}

// memcachedValidRequestFields validates the token count and integer-valued
// fields for a given command.
func memcachedValidRequestFields(fields [][]byte, op string, noreply bool) bool {
	fieldCount := len(fields)

	switch op {
	case "GET":
		return fieldCount >= 2
	case "GAT":
		return fieldCount >= 3 && memcachedSignedIntField(fields[1])
	case "SET", "ADD", "REPLACE", "APPEND", "PREPEND":
		return memcachedMatchesFieldCount(fieldCount, noreply, 5) && memcachedSignedIntField(fields[3]) && memcachedSignedIntField(fields[4])
	case "CAS":
		return memcachedMatchesFieldCount(fieldCount, noreply, 6) && memcachedSignedIntField(fields[3]) && memcachedSignedIntField(fields[4])
	case "DELETE":
		return memcachedMatchesFieldCount(fieldCount, noreply, 2)
	case "INCR", "DECR":
		return memcachedMatchesFieldCount(fieldCount, noreply, 3)
	case "TOUCH":
		return memcachedMatchesFieldCount(fieldCount, noreply, 3) && memcachedSignedIntField(fields[2])
	case "FLUSH_ALL":
		if noreply {
			if fieldCount == 2 {
				return true
			}
			return fieldCount == 3 && memcachedSignedIntField(fields[1])
		}
		if fieldCount == 1 {
			return true
		}
		return fieldCount == 2 && memcachedSignedIntField(fields[1])
	case "STATS":
		return fieldCount >= 1
	case "VERSION":
		return fieldCount == 1
	default:
		return false
	}
}

func memcachedMatchesFieldCount(fieldCount int, noreply bool, base int) bool {
	if noreply {
		return fieldCount == base+1
	}

	return fieldCount == base
}

// memcachedSignedIntField reports whether a token is an ASCII decimal integer
// with an optional leading minus sign.
func memcachedSignedIntField(field []byte) bool {
	if len(field) == 0 {
		return false
	}
	if field[0] == '-' {
		field = field[1:]
	}
	if len(field) == 0 {
		return false
	}

	for _, b := range field {
		if b < '0' || b > '9' {
			return false
		}
	}

	return true
}
