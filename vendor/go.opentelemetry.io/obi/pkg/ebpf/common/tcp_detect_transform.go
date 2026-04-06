// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
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
//
//nolint:cyclop
func ReadTCPRequestIntoSpan(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(app.PID(event.Pid.UserPid), event.Pid.Ns, PIDTypeKProbes) {
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

	// We might know already the protocol for this event
	switch event.ProtocolType {
	case ProtocolTypeKafka:
		k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed kafka event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToKafkaToSpan(event, k), false, nil
		}
		return request.Span{}, true, fmt.Errorf("failed to handle Kafka event: %w", err)
	case ProtocolTypeMQTT:
		m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed MQTT event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToMQTTToSpan(event, m), false, nil
		}
		return request.Span{}, true, fmt.Errorf("failed to handle MQTT event: %w", err)
	case ProtocolTypeMySQL:
		span, err := handleMySQL(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Debug("MySQL: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle MySQL event: %w", err)
		}

		return span, false, nil
	case ProtocolTypePostgres:
		span, err := handlePostgres(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Debug("Postgres: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle Postgres event: %w", err)
		}

		return span, false, nil
	case ProtocolTypeUnknown:
	default:
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)
		if validSQL(op, table, kind) {
			reverseTCPEvent(event)
			return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
		}
	}

	if maybeFastCGI(requestBuffer) {
		op, uri, status := detectFastCGI(requestBuffer, responseBuffer)
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, nil
		}
	}
	mongoInfo := mongoInfoFromEvent(event, requestBuffer, responseBuffer, parseCtx.mongoRequestCache)
	if mongoInfo != nil {
		mongoSpan := TCPToMongoToSpan(event, mongoInfo)
		return mongoSpan, false, nil
	}

	// Check for Couchbase memcached binary protocol
	cbInfo, ignore, err := ProcessPossibleCouchbaseEvent(event, requestBuffer, responseBuffer, parseCtx.couchbaseBucketCache)
	if err == nil {
		if ignore {
			return request.Span{}, true, nil
		}
		if cbInfo != nil {
			return TCPToCouchbaseToSpan(event, cbInfo), false, nil
		}
	}

	// Request-only events are emitted on socket close.
	// They might contain requests like memcached with noreply that we haven't seen the response for.
	if responseBuffer.Len() == 0 {
		requestReader := requestBuffer.NewReader()
		if ops, ok := parseMemcachedExplicitNoreply(&requestReader); ok {
			emitMemcachedNoreplySpans(parseCtx, event, ops)
			return request.Span{}, true, nil
		}
	}

	switch {
	case isRedis(requestBuffer) && isRedis(responseBuffer):
		op, text, ok := parseRedisRequest(requestBuffer.UnsafeView())

		if ok {
			var status int
			var redisErr request.DBError
			if op == "" {
				op, text, ok = parseRedisRequest(responseBuffer.UnsafeView())
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
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
			return TCPToRedisToSpan(event, op, text, status, db, redisErr), false, nil
		}
	case isMemcached(requestBuffer, responseBuffer):
		span, err := ProcessPossibleMemcachedEvent(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle Memcached event: %w", err)
		}
		return span, false, nil
	// must come before MQTT: the MQTT heuristic can match the HTTP/2 connection preface,
	// silently dropping packets that should be re-routed as HTTP/2
	case isHTTP2(requestBuffer, int(event.Len)) || isHTTP2(responseBuffer, int(event.RespLen)):
		evCopy := *event
		MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}
		return request.Span{}, true, nil // ignore for now, next event will be parsed
	case isMQTT(requestBuffer) || isMQTT(responseBuffer):
		m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed MQTT event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToMQTTToSpan(event, m), false, nil
		}
		// MQTT heuristic matched but full parsing failed - ignore the packet
		slog.Debug("MQTT heuristic detection failed, ignoring", "error", err)
	default:
		// Kafka can arrive here for packets the kernel couldn't classify (e.g. OBI attached mid-connection).
		k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed kafka event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToKafkaToSpan(event, k), false, nil
		}
	}

	if cfg.ProtocolDebug {
		fmt.Printf("![>] %v\n", requestBuffer.UnsafeView())
		fmt.Printf("![<] %v\n", responseBuffer.UnsafeView())
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
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
