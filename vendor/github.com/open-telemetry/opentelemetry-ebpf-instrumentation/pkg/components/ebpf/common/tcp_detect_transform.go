package ebpfcommon

import (
	"fmt"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/sqlprune"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/config"
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

	var requestBuffer, responseBuffer []byte

	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	requestBuffer = event.Buf[:l]

	l = int(event.RespLen)
	if l < 0 || len(event.Rbuf) < l {
		l = len(event.Rbuf)
	}
	responseBuffer = event.Rbuf[:l]

	if event.HasLargeBuffers == 1 {
		if b, ok := getTCPLargeBuffer(parseCtx, event.Tp.TraceId, event.Tp.SpanId, 0); ok {
			requestBuffer = b
		}
		if b, ok := getTCPLargeBuffer(parseCtx, event.Tp.TraceId, event.Tp.SpanId, 1); ok {
			responseBuffer = b
		}
	}

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", requestBuffer)
		fmt.Printf("[<] %v\n", responseBuffer)
	}

	// We might know already the protocol for this event
	switch event.ProtocolType {
	case ProtocolTypeMySQL: // MySQL
		if len(requestBuffer) < sqlprune.MySQLHdrSize+1 {
			slog.Warn("MySQL request too short, falling back to generic handler", "len", len(requestBuffer))
			break
		}

		sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, requestBuffer)
		if sqlCommand == "" {
			slog.Warn("MySQL command ID unhandled", "commandID", requestBuffer[sqlprune.MySQLHdrSize])
			return request.Span{}, true, nil
		}

		var op, table string
		stmt := string(requestBuffer[sqlprune.MySQLHdrSize+1:])
		defer func() {
			if r := recover(); r != nil {
				slog.Error("recovered from panic in SQLParseOperationAndTableNEW", "error", r)
				op = ""
				table = ""
			}
		}()

		op, table = sqlprune.SQLParseOperationAndTableNEW(stmt)
		if !validSQL(op, table, request.DBMySQL) {
			slog.Warn("MySQL operation and/or table are invalid, falling back to generic handler", "stmt", stmt)
			break
		}

		return TCPToSQLToSpan(event, op, table, stmt, request.DBMySQL, requestBuffer, responseBuffer, sqlCommand), false, nil
	case ProtocolTypeUnknown:
	default:
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind, requestBuffer, responseBuffer, ""), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)
		if validSQL(op, table, kind) {
			reverseTCPEvent(event)
			return TCPToSQLToSpan(event, op, table, sql, kind, requestBuffer, responseBuffer, ""), false, nil
		}
	}

	if maybeFastCGI(requestBuffer) {
		op, uri, status := detectFastCGI(requestBuffer, responseBuffer)
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, nil
		}
	}

	var mongoRequest *MongoRequestValue
	var moreToCome bool
	_, _, err = ProcessMongoEvent(requestBuffer, int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, *parseCtx.mongoRequestCache)
	if err == nil {
		mongoRequest, moreToCome, err = ProcessMongoEvent(event.Rbuf[:l], int64(event.StartMonotimeNs), int64(event.EndMonotimeNs), event.ConnInfo, *parseCtx.mongoRequestCache)
	}
	if err == nil && !moreToCome && mongoRequest != nil {
		mongoInfo, err := getMongoInfo(mongoRequest)
		if err == nil {
			mongoSpan := TCPToMongoToSpan(event, mongoInfo)
			return mongoSpan, false, nil
		}
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
			k, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer)
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
