package ebpfcommon

import (
	"fmt"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/config"
)

// ReadTCPRequestIntoSpan returns a request.Span from the provided ring buffer record
//
//nolint:cyclop
func ReadTCPRequestIntoSpan(parseContext *EBPFParseContext, cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}

	rl := int(event.RespLen)
	if rl < 0 || len(event.Rbuf) < rl {
		rl = len(event.Rbuf)
	}

	b := event.Buf[:l]

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", b)
		fmt.Printf("[<] %v\n", event.Rbuf[:rl])
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, b)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, event.Rbuf[:rl])
		if validSQL(op, table, kind) {
			reverseTCPEvent(event)

			return TCPToSQLToSpan(event, op, table, sql, kind), false, nil
		}
	}

	if maybeFastCGI(b) {
		op, uri, status := detectFastCGI(b, event.Rbuf[:rl])
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, nil
		}
	}

	switch {
	case isRedis(b) && isRedis(event.Rbuf[:rl]):
		op, text, ok := parseRedisRequest(string(b))

		if ok {
			var status int
			var redisErr request.DBError
			if op == "" {
				op, text, ok = parseRedisRequest(string(event.Rbuf[:rl]))
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
				}
				// We've caught the event reversed in the middle of communication, let's
				// reverse the event
				reverseTCPEvent(event)
				redisErr, status = redisStatus(b)
			} else {
				redisErr, status = redisStatus(event.Rbuf[:rl])
			}

			db, found := getRedisDB(event.ConnInfo, op, text, parseContext.redisDBCache)
			if !found {
				db = -1 // if we don't have the db in cache, we assume it's not set
			}
			return TCPToRedisToSpan(event, op, text, status, db, redisErr), false, nil
		}
	default:
		// Kafka and gRPC can look very similar in terms of bytes. We can mistake one for another.
		// We try gRPC first because it's more reliable in detecting false gRPC sequences.
		if isHTTP2(b, int(event.Len)) || isHTTP2(event.Rbuf[:rl], int(event.RespLen)) {
			evCopy := *event
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}
		} else {
			k, err := ProcessPossibleKafkaEvent(event, b, event.Rbuf[:rl])
			if err == nil {
				return TCPToKafkaToSpan(event, k), false, nil
			}
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
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
