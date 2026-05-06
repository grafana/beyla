// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

var (
	errFallback = errors.New("falling back to generic handler")
	errIgnore   = errors.New("ignoring event")
)

const (
	packetTypeRequest  = 1
	packetTypeResponse = 2

	directionRecv = 0
	directionSend = 1
)

// ReadTCPRequestIntoSpan returns a request.Span from the provided ring buffer record
func ReadTCPRequestIntoSpan(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if event.EventSource == GenericEventSourceTypeKProbes && !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	requestBuffer, responseBuffer := getBuffers(parseCtx, event)

	if cfg.ProtocolDebug {
		slog.Debug("ReadTCPRequestIntoSpan: received TCP event",
			"pid", event.Pid.UserPid,
			"ns", event.Pid.Ns,
			"protocol", event.ProtocolType,
			"reqLen", event.Len,
			"respLen", event.RespLen)
		fmt.Printf("[>] %v\n", requestBuffer.UnsafeView())
		fmt.Printf("[<] %v\n", responseBuffer.UnsafeView())
	}

	if span, ignore, matched, err := dispatchKernelAssignedProtocol(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, err
	}

	if span, ignore, matched, err := detectGenericProtocol(parseCtx, cfg, event, requestBuffer, responseBuffer); matched {
		return span, ignore, err
	}

	if span, ignore, matched, err := detectHeuristicProtocol(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, err
	}

	if cfg.ProtocolDebug {
		fmt.Printf("![>] %v\n", requestBuffer.UnsafeView())
		fmt.Printf("![<] %v\n", responseBuffer.UnsafeView())
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

// dispatchKernelAssignedProtocol handles events where the kernel has already classified the protocol.
// returns matched=false for ProtocolTypeUnknown or when MySQL/Postgres fall back to generic detection.
func dispatchKernelAssignedProtocol(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	switch event.ProtocolType {
	case ProtocolTypeKafka:
		return dispatchKafka(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
	case ProtocolTypeMQTT:
		return dispatchMQTT(event, requestBuffer, responseBuffer)
	case ProtocolTypeMySQL:
		return dispatchMySQL(parseCtx, event, requestBuffer, responseBuffer)
	case ProtocolTypePostgres:
		return dispatchPostgres(parseCtx, event, requestBuffer, responseBuffer)
	case ProtocolTypeMSSQL:
		return dispatchMSSQL(parseCtx, event, requestBuffer, responseBuffer)
	}

	return request.Span{}, false, false, nil
}

func dispatchKafka(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (request.Span, bool, bool, error) {
	k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, kafkaTopicUUIDToName)

	if ignore && err == nil {
		return request.Span{}, true, true, nil // parsed kafka event, but we don't want to create a span for it
	}

	if err == nil {
		return TCPToKafkaToSpan(event, k), false, true, nil
	}

	return request.Span{}, true, true, fmt.Errorf("failed to handle Kafka event: %w", err)
}

func dispatchMQTT(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)

	if ignore && err == nil {
		return request.Span{}, true, true, nil // parsed MQTT event, but we don't want to create a span for it
	}

	if err == nil {
		return TCPToMQTTToSpan(event, m), false, true, nil
	}

	return request.Span{}, true, true, fmt.Errorf("failed to handle MQTT event: %w", err)
}

func handleError(span request.Span, err error, name string) (request.Span, bool, bool, error) {
	if errors.Is(err, errFallback) {
		slog.Debug("falling back to generic handler", "protocol", name)
		return request.Span{}, false, false, nil
	}

	if errors.Is(err, errIgnore) {
		return request.Span{}, true, true, nil
	}

	if err != nil {
		return request.Span{}, true, true, fmt.Errorf("failed to handle %s event: %w", name, err)
	}

	return span, false, true, nil
}

func dispatchMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	span, err := handleMySQL(parseCtx, event, requestBuffer, responseBuffer)
	return handleError(span, err, "MySQL")
}

func dispatchPostgres(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	span, err := handlePostgres(parseCtx, event, requestBuffer, responseBuffer)
	return handleError(span, err, "Postgres")
}

func dispatchMSSQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	span, err := handleMSSQL(parseCtx, event, requestBuffer, responseBuffer)
	return handleError(span, err, "MSSQL")
}

// detectGenericProtocol runs deterministic protocol detection for unclassified events:
// SQL, FastCGI, MongoDB, Couchbase, and Memcached noreply.
func detectGenericProtocol(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	if span, ignore, matched, err := matchSQL(cfg, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchFastCGI(event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchMongo(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchCouchbase(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchMemcachedNoreply(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	return request.Span{}, false, false, nil
}

func matchSQL(cfg *config.EBPFTracer, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)

	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, true, nil
	}

	op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)

	if validSQL(op, table, kind) {
		reverseTCPEvent(event)
		return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, true, nil
	}

	return request.Span{}, false, false, nil
}

func matchFastCGI(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if maybeFastCGI(requestBuffer) {
		op, uri, status := detectFastCGI(requestBuffer, responseBuffer)
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, true, nil
		}
	}
	return request.Span{}, false, false, nil
}

func matchMongo(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if mongoInfo := mongoInfoFromEvent(event, requestBuffer, responseBuffer, parseCtx.mongoRequestCache); mongoInfo != nil {
		return TCPToMongoToSpan(event, mongoInfo), false, true, nil
	}
	return request.Span{}, false, false, nil
}

func matchCouchbase(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	// Check for Couchbase memcached binary protocol
	cbInfo, ignore, err := ProcessPossibleCouchbaseEvent(event, requestBuffer, responseBuffer, parseCtx.couchbaseBucketCache)

	if err == nil {
		if ignore {
			return request.Span{}, true, true, nil
		}

		if cbInfo != nil {
			return TCPToCouchbaseToSpan(event, cbInfo), false, true, nil
		}
	}

	return request.Span{}, false, false, nil
}

func matchMemcachedNoreply(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	// Request-only events are emitted on socket close.
	// They might contain requests like memcached with noreply that we haven't seen the response for.
	if responseBuffer.Len() == 0 {
		requestReader := requestBuffer.NewReader()
		if ops, ok := parseMemcachedExplicitNoreply(&requestReader); ok {
			emitMemcachedNoreplySpans(parseCtx, event, ops)
			return request.Span{}, true, true, nil
		}
	}
	return request.Span{}, false, false, nil
}

// detectHeuristicProtocol runs heuristic-based protocol detection as a last resort:
// Redis, Memcached, HTTP/2, NATS, MQTT, and Kafka (for packets the kernel couldn't classify).
func detectHeuristicProtocol(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	if span, ignore, matched, err := matchRedis(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchMemcached(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	// must come before MQTT: the MQTT heuristic can match the HTTP/2 connection preface,
	// silently dropping packets that should be re-routed as HTTP/2
	// We also must check for the event source here, since now generic TCP events can come from
	// the Go tracer. The backup path for HTTP2 should only run for generic kprobe events.
	if event.EventSource == GenericEventSourceTypeKProbes {
		if span, ignore, matched, err := matchHTTP2(event, requestBuffer, responseBuffer); matched {
			return span, ignore, matched, err
		}
	}
	if span, ignore, matched, err := matchNATS(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}
	if span, ignore, matched, err := matchMQTT(event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	// Kafka can arrive here for packets the kernel couldn't classify (e.g. OBI attached mid-connection).
	if span, ignore, matched, err := matchKafkaFallback(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName); matched {
		return span, ignore, matched, err
	}

	return request.Span{}, false, false, nil
}

func matchRedis(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if !isRedis(requestBuffer) || !isRedis(responseBuffer) {
		return request.Span{}, false, false, nil
	}

	op, text, ok := parseRedisRequest(requestBuffer.UnsafeView())

	if !ok {
		return request.Span{}, false, false, nil
	}

	var status int
	var redisErr request.DBError

	if op == "" {
		op, text, ok = parseRedisRequest(responseBuffer.UnsafeView())
		if !ok || op == "" {
			return request.Span{}, true, true, nil // ignore if we couldn't parse it
		}
		// We've caught the event reversed in the middle of communication, let's
		// reverse the event
		reverseTCPEvent(event)
		redisErr, status = redisStatus(requestBuffer)
	} else {
		redisErr, status = redisStatus(responseBuffer)
	}

	db, found := getRedisDB(event.ConnInfo, op, text, parseCtx.redisDBCache)

	if !found {
		db = -1 // if we don't have the db in cache, we assume it's not set
	}

	return TCPToRedisToSpan(event, op, text, status, db, redisErr), false, true, nil
}

func matchMemcached(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	if !isMemcached(requestBuffer, responseBuffer) {
		return request.Span{}, false, false, nil
	}

	span, err := ProcessPossibleMemcachedEvent(parseCtx, event, requestBuffer, responseBuffer)

	if errors.Is(err, errIgnore) {
		return request.Span{}, true, true, nil
	}

	if err != nil {
		return request.Span{}, true, true, fmt.Errorf("failed to handle Memcached event: %w", err)
	}

	return span, false, true, nil
}

func matchHTTP2(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if !isHTTP2(requestBuffer, int(event.Len)) && !isHTTP2(responseBuffer, int(event.RespLen)) {
		return request.Span{}, false, false, nil
	}

	evCopy := *event
	MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}

	return request.Span{}, true, true, nil // ignore for now, next event will be parsed
}

func matchNATS(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	info, extraInfo, ignore, err := ProcessPossibleNATSEvent(event, requestBuffer, responseBuffer)

	if ignore && err == nil {
		return request.Span{}, true, true, nil
	}

	if err != nil {
		return request.Span{}, false, false, nil
	}

	if extraInfo != nil {
		extraSpan := TCPToNATSToSpan(event, extraInfo)
		extraSpan.Type = request.EventTypeNATSServer
		extraSpan.SpanID = trace.SpanID{}

		parseCtx.emitExtraSpans(extraSpan)
	}
	return TCPToNATSToSpan(event, info), false, true, nil
}

func matchMQTT(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if !isMQTT(requestBuffer) && !isMQTT(responseBuffer) {
		return request.Span{}, false, false, nil
	}

	m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)

	if ignore && err == nil {
		return request.Span{}, true, true, nil // parsed MQTT event, but we don't want to create a span for it
	}

	if err == nil {
		return TCPToMQTTToSpan(event, m), false, true, nil
	}

	// MQTT heuristic matched but full parsing failed - ignore the packet
	slog.Debug("MQTT heuristic detection failed, ignoring", "error", err)

	return request.Span{}, false, false, nil
}

// matchKafkaFallback handles Kafka for unclassified packets (e.g. when the kernel missed the
// connection start). Unlike dispatchKafka, errors here mean "not Kafka" — no error is surfaced.
func matchKafkaFallback(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (request.Span, bool, bool, error) { //nolint:unparam
	k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, kafkaTopicUUIDToName)

	if ignore && err == nil {
		return request.Span{}, true, true, nil // parsed kafka event, but we don't want to create a span for it
	}

	if err == nil {
		return TCPToKafkaToSpan(event, k), false, true, nil
	}

	return request.Span{}, false, false, nil
}

func getBuffers(parseCtx *EBPFParseContext, event *TCPRequestInfo) (req *largebuf.LargeBuffer, resp *largebuf.LargeBuffer) {
	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	req = largebuf.NewLargeBufferFrom(event.Buf[:l])

	l = int(event.RespLen)
	if l < 0 || len(event.Rbuf) < l {
		l = len(event.Rbuf)
	}
	resp = largebuf.NewLargeBufferFrom(event.Rbuf[:l])

	if event.HasLargeBuffers == 1 {
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, !event.IsServer), event.ConnInfo); ok {
			req = b
		}
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, !event.IsServer), event.ConnInfo); ok {
			resp = b
		}
	}

	return
}

func reverseTCPEvent(trace *TCPRequestInfo) {
	if trace.Direction == 0 {
		trace.Direction = 1
	} else {
		trace.Direction = 0
	}

	port := trace.ConnInfo.S_port
	addr := trace.ConnInfo.S_addr
	trace.ConnInfo.S_addr = trace.ConnInfo.D_addr
	trace.ConnInfo.S_port = trace.ConnInfo.D_port
	trace.ConnInfo.D_addr = addr
	trace.ConnInfo.D_port = port
}
