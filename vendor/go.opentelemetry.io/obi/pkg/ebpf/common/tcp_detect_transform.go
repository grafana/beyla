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
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/kafkaparser"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/mqttparser"
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
		return dispatchKafka(parseCtx, event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
	case ProtocolTypeMQTT:
		return dispatchMQTT(event, requestBuffer, responseBuffer)
	case ProtocolTypeMySQL:
		return dispatchMySQL(parseCtx, event, requestBuffer, responseBuffer)
	case ProtocolTypePostgres:
		return dispatchPostgres(parseCtx, event, requestBuffer, responseBuffer)
	case ProtocolTypeMSSQL:
		return dispatchMSSQL(parseCtx, event, requestBuffer, responseBuffer)
	case ProtocolTypeSunRPC:
		return dispatchSunRPC(event, requestBuffer, responseBuffer)
	}

	return request.Span{}, false, false, nil
}

// handleKafkaEvent runs the common Kafka parse-and-emit path shared by dispatchKafka and
// matchKafkaFallback. On a parse failure it returns the raw error; the caller decides whether
// to surface it (classified packet) or swallow it as "not Kafka" (fallback path).
func handleKafkaEvent(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (request.Span, bool, bool, error) {
	infos, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, kafkaTopicUUIDToName)

	if ignore && err == nil {
		return request.Span{}, true, true, nil // parsed kafka event, but we don't want to create a span for it
	}

	if err == nil {
		if span, ok := kafkaSpanEmittingExtras(parseCtx, event, infos); ok {
			return span, false, true, nil
		}
		return request.Span{}, true, true, nil // no topics to report
	}

	return request.Span{}, false, false, err
}

func dispatchKafka(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (request.Span, bool, bool, error) {
	span, ignore, matched, err := handleKafkaEvent(parseCtx, event, requestBuffer, responseBuffer, kafkaTopicUUIDToName)
	if err != nil {
		return request.Span{}, true, true, fmt.Errorf("failed to handle Kafka event: %w", err)
	}
	return span, ignore, matched, nil
}

// kafkaSpanEmittingExtras turns the per-topic KafkaInfos of one Produce/Fetch request into spans.
// A request can reference multiple topics; we return the span for the first topic and emit the rest
// as extra spans (each gets a fresh SpanID downstream, since they share the event's trace context).
func kafkaSpanEmittingExtras(parseCtx *EBPFParseContext, event *TCPRequestInfo, infos []*KafkaInfo) (request.Span, bool) {
	if len(infos) == 0 {
		return request.Span{}, false
	}
	primary := TCPToKafkaToSpan(event, infos[0])
	if len(infos) > 1 {
		extra := make([]request.Span, 0, len(infos)-1)
		for _, info := range infos[1:] {
			s := TCPToKafkaToSpan(event, info)
			// Zero the SpanID so the pipeline assigns a unique one; otherwise every
			// topic span from this request would share the event's SpanID.
			s.SpanID = trace.SpanID{}
			extra = append(extra, s)
		}
		parseCtx.emitExtraSpans(extra...)
	}
	return primary, true
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

func dispatchSunRPC(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	info, ignore, err := ProcessPossibleSunRPCEvent(event, requestBuffer, responseBuffer)

	if ignore && err == nil {
		return request.Span{}, true, true, nil
	}

	if err == nil {
		return TCPToSunRPCToSpan(event, info), false, true, nil
	}

	return request.Span{}, true, true, fmt.Errorf("failed to handle SunRPC event: %w", err)
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
	if span, ignore, matched, err := matchSQL(parseCtx, cfg, event, requestBuffer, responseBuffer); matched {
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

// caches the connection's database name for the SQL spans that follow
func matchPostgresStartup(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if parseCtx.postgresDBNames == nil {
		return request.Span{}, false, false, nil
	}

	if db, ok := parsePostgresStartup(requestBuffer); ok {
		parseCtx.postgresDBNames.Add(event.ConnInfo, db)
		return request.Span{}, true, true, nil
	}

	// caught reversed in the middle of communication
	if db, ok := parsePostgresStartup(responseBuffer); ok {
		parseCtx.postgresDBNames.Add(reverseTCPConnInfo(event.ConnInfo), db)
		return request.Span{}, true, true, nil
	}

	return request.Span{}, false, false, nil
}

func matchSQL(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) {
	if span, ignore, matched, err := matchPostgresStartup(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	op, tables, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)

	if validSQL(op, len(tables) > 0, kind) {
		span := TCPToSQLToSpan(event, op, tables, sql, kind, "", nil)
		if kind == request.DBPostgres {
			span.DBNamespace = postgresDBForConn(parseCtx, event.ConnInfo)
		}
		return span, false, true, nil
	}

	op, tables, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)

	if validSQL(op, len(tables) > 0, kind) {
		reverseTCPEvent(event)
		span := TCPToSQLToSpan(event, op, tables, sql, kind, "", nil)
		if kind == request.DBPostgres {
			span.DBNamespace = postgresDBForConn(parseCtx, event.ConnInfo)
		}
		return span, false, true, nil
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
// Redis, Memcached, HTTP/2, NATS, AMQP, MQTT, Kafka (for packets the kernel couldn't classify),
// and SunRPC (fallback when the kernel missed the connection start).
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
	if span, ignore, matched, err := matchAMQP(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}
	if span, ignore, matched, err := matchMQTT(event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	// Kafka can arrive here for packets the kernel couldn't classify (e.g. OBI attached mid-connection).
	if span, ignore, matched, err := matchKafkaFallback(parseCtx, event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName); matched {
		return span, ignore, matched, err
	}

	// SunRPC can arrive here when the kernel missed the connection start (e.g. OBI attached mid-connection).
	if span, ignore, matched, err := matchSunRPC(parseCtx, event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	if span, ignore, matched, err := matchAerospike(event, requestBuffer, responseBuffer); matched {
		return span, ignore, matched, err
	}

	return request.Span{}, false, false, nil
}

// matchAerospike detects the Aerospike native client protocol (proto v2) from the
// captured request/response buffers and builds a client span. Only type-3 AS_MSG
// data requests produce a span; info/auth/compressed frames are left for the
// generic ignore path. Correlation is the generic per-connection direction flip.
func matchAerospike(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	// Aerospike instrumentation is client-side only. When OBI also instruments the
	// Aerospike server process it sees the same exchange from the server side; skip
	// it so a single operation isn't reported twice (once per peer).
	if event.IsServer {
		return request.Span{}, false, false, nil
	}

	// parseAerospikeRequest validates the proto/as_msg header itself and returns
	// nil for non-Aerospike or response frames, so it doubles as the detector.
	if info := parseAerospikeRequest(requestBuffer); info != nil {
		status, dbError := aerospikeStatus(responseBuffer)
		return TCPToAerospikeToSpan(event, info, status, dbError), false, true, nil
	}

	// We may have caught the connection mid-flight with the buffers reversed.
	if info := parseAerospikeRequest(responseBuffer); info != nil {
		reverseTCPEvent(event)
		status, dbError := aerospikeStatus(requestBuffer)
		return TCPToAerospikeToSpan(event, info, status, dbError), false, true, nil
	}

	return request.Span{}, false, false, nil
}

func matchRedis(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	if !isRedis(requestBuffer) || !isRedis(responseBuffer) {
		return request.Span{}, false, false, nil
	}

	cmds := parseRedisCommands(requestBuffer.UnsafeView())
	reversed := false

	// mid-flight attach can swap buffer roles (blocking-command replies arrive
	// receive-first); the side holding a known command word wins
	if len(cmds) == 0 || !isKnownRedisOp(cmds[0].op) {
		if respCmds := parseRedisCommands(responseBuffer.UnsafeView()); len(respCmds) > 0 &&
			(len(cmds) == 0 || isKnownRedisOp(respCmds[0].op)) {
			cmds = respCmds
			reversed = true
			reverseTCPEvent(event)
		}
	}

	if len(cmds) == 0 {
		return request.Span{}, true, true, nil // redis reply traffic with no command to attribute
	}

	// reversed events pair the commands with a stale reply, so statuses are unknowable
	var replies []redisReply
	if !reversed {
		replies = parseRedisReplies(responseBuffer.UnsafeView(), len(cmds))
	}

	spans := make([]request.Span, 0, len(cmds))
	for i := range cmds {
		cmd := &cmds[i]

		status := 0
		var redisErr request.DBError
		if i < len(replies) {
			status, redisErr = replies[i].status, replies[i].dbError
		}

		db, found := getRedisDB(event.ConnInfo, cmd.op, cmd.text, parseCtx.redisDBCache)
		if !found {
			db = -1 // if we don't have the db in cache, we assume it's not set
		}

		spans = append(spans, TCPToRedisToSpan(event, cmd.op, cmd.text, status, db, redisErr))
	}

	if len(spans) > 1 {
		// clear SpanID on extras so tracesgen assigns fresh IDs
		for i := 1; i < len(spans); i++ {
			spans[i].SpanID = trace.SpanID{}
		}
		parseCtx.emitExtraSpans(spans[1:]...)
	}

	return spans[0], false, true, nil
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

func matchAMQP(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	infos, ignore, err := ProcessPossibleAMQPEvent(event, requestBuffer, responseBuffer)
	if ignore && err == nil {
		return request.Span{}, true, true, nil
	}

	if err == nil {
		spans := make([]request.Span, 0, len(infos))
		for _, info := range infos {
			spans = append(spans, TCPToAMQPToSpan(event, info))
		}
		if len(spans) == 0 {
			return request.Span{}, true, true, nil
		}
		if len(spans) > 1 {
			// Clear SpanID on extras so tracesgen assigns fresh IDs; otherwise
			// every clone exports with the captured SpanID, violating OTel.
			for i := 1; i < len(spans); i++ {
				spans[i].SpanID = trace.SpanID{}
			}
			parseCtx.emitExtraSpans(spans[1:]...)
		}
		return spans[0], false, true, nil
	}

	if errors.Is(err, amqpparser.ErrNotAMQP) {
		return request.Span{}, false, false, nil
	}

	slog.Debug("AMQP parsing failed after heuristic match, dropping event", "error", err)
	return request.Span{}, true, true, nil
}

func matchMQTT(event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, bool, bool, error) { //nolint:unparam
	isLikelyMQTT := func(pkt *largebuf.LargeBuffer) bool {
		first, err := pkt.U8At(0)

		return err == nil && mqttparser.IsLikelyMQTT(first, pkt.Len())
	}
	// Cheap prefilter: if neither buffer has a plausible MQTT fixed-header
	// byte 0, skip the variable-length parsing entirely.
	if !isLikelyMQTT(requestBuffer) && !isLikelyMQTT(responseBuffer) {
		return request.Span{}, false, false, nil
	}

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
func matchKafkaFallback(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (request.Span, bool, bool, error) { //nolint:unparam
	span, ignore, matched, err := handleKafkaEvent(parseCtx, event, requestBuffer, responseBuffer, kafkaTopicUUIDToName)
	if err != nil {
		return request.Span{}, false, false, nil // parse failed on an unclassified packet — treat as "not Kafka"
	}
	return span, ignore, matched, nil
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
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, !event.IsServer), event.ConnInfo, event.ProtocolType); ok {
			req = b
		}
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, !event.IsServer), event.ConnInfo, event.ProtocolType); ok {
			resp = b
		}
	}

	return req, resp
}

func reverseTCPEvent(trace *TCPRequestInfo) {
	trace.Direction = reverseDirection(trace.Direction)
	trace.ConnInfo = reverseTCPConnInfo(trace.ConnInfo)
}

func reverseDirection(direction uint8) uint8 {
	if direction == directionSend {
		return directionRecv
	}
	return directionSend
}

func reverseTCPConnInfo(conn BpfConnectionInfoT) BpfConnectionInfoT {
	conn.S_addr, conn.D_addr = conn.D_addr, conn.S_addr
	conn.S_port, conn.D_port = conn.D_port, conn.S_port
	return conn
}
