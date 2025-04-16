package ebpfcommon

import (
	"fmt"
	"regexp"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/ringbuf"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

var (
	// Match tokens, passwords, auth data, and similar sensitive patterns
	tokenPattern = regexp.MustCompile(`(?i)(token|password|auth|secret|key|credential|jwt)["']?\s*[:=]\s*["']?([^"'\s,\}]+)`)
	// Match for JSON, XML and plain values that might contain sensitive info
	sessionDataPattern = regexp.MustCompile(`(?i)(s:[0-9]+:["'])([^"']+)(["'])`)
	// Redis AUTH command
	redisAuthPattern = regexp.MustCompile(`(?i)(AUTH\s+)(\S+)`)
	// Redis SETEX command (which often contains sensitive session data)
	redisSetexPattern = regexp.MustCompile(`(?i)(SETEX\s+\S+\s+\d+\s+)(.+)`)
)

// sanitizeBuffer masks sensitive data in protocol buffers before logging
func sanitizeBuffer(data []byte) []byte {
	if len(data) == 0 {
		return data
	}

	content := string(data)

	// Replace sensitive pattern matches with masked data
	content = tokenPattern.ReplaceAllString(content, "$1: \"***REDACTED***\"")
	content = sessionDataPattern.ReplaceAllString(content, "$1***REDACTED***$3")
	content = redisAuthPattern.ReplaceAllString(content, "$1***REDACTED***")
	content = redisSetexPattern.ReplaceAllString(content, "$1***REDACTED***")

	return []byte(content)
}

// nolint:cyclop
func ReadTCPRequestIntoSpan(cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
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
		sanitizedReq := sanitizeBuffer(b)
		sanitizedResp := sanitizeBuffer(event.Rbuf[:rl])
		fmt.Printf("[>] %q\n", sanitizedReq)
		fmt.Printf("[<] %q\n", sanitizedResp)
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
			if op == "" {
				op, text, ok = parseRedisRequest(string(event.Rbuf[:rl]))
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
				}
				// We've caught the event reversed in the middle of communication, let's
				// reverse the event
				reverseTCPEvent(event)
				status = redisStatus(b)
			} else {
				status = redisStatus(event.Rbuf[:rl])
			}

			return TCPToRedisToSpan(event, op, text, status), false, nil
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
