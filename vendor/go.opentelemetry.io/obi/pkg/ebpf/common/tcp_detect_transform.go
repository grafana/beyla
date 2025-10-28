// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
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

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	requestBuffer, responseBuffer := getBuffers(parseCtx, event)

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", requestBuffer)
		fmt.Printf("[<] %v\n", responseBuffer)
	}

	// We might know already the protocol for this event
	switch event.ProtocolType {
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

	switch {
	case isRedis(requestBuffer) && isRedis(responseBuffer):
		op, text, ok := parseRedisRequest(string(requestBuffer))

		if ok {
			var status int
			var redisErr request.DBError
			if op == "" {
				op, text, ok = parseRedisRequest(string(responseBuffer))
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
	default:
		// Kafka and gRPC can look very similar in terms of bytes. We can mistake one for another.
		// We try gRPC first because it's more reliable in detecting false gRPC sequences.
		if isHTTP2(requestBuffer, int(event.Len)) || isHTTP2(responseBuffer, int(event.RespLen)) {
			evCopy := *event
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}
		} else {
			k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
			if ignore {
				return request.Span{}, true, nil // parsed kafka event, but we don't want to create a span for it
			}
			if err == nil {
				return TCPToKafkaToSpan(event, k), false, nil
			}
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func getBuffers(parseCtx *EBPFParseContext, event *TCPRequestInfo) (req []byte, resp []byte) {
	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	req = event.Buf[:l]

	l = int(event.RespLen)
	if l < 0 || len(event.Rbuf) < l {
		l = len(event.Rbuf)
	}
	resp = event.Rbuf[:l]

	if event.HasLargeBuffers == 1 {
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionSend, event.ConnInfo); ok {
			req = b
		}
		if b, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionRecv, event.ConnInfo); ok {
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
