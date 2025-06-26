package ebpfcommon

import (
	"bytes"
	"strings"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/util"
)

const minRedisFrameLen = 3

var redisErrorCodes = [...]string{
	"ERR ",
	"WRONGTYPE ",
	"MOVED ",
	"ASK ",
	"BUSY ",
	"NOSCRIPT ",
	"CLUSTERDOWN ",
	"READONLY ",
}

func isRedis(buf []uint8) bool {
	if len(buf) < minRedisFrameLen {
		return false
	}

	return isRedisOp(buf)
}

//nolint:cyclop
func isRedisOp(buf []uint8) bool {
	if len(buf) == 0 {
		return false
	}
	c := buf[0]

	switch c {
	case '+':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == ' ' || c == '-' || c == '_'
		})
	case '-':
		_, isError := getRedisError(buf[1:])
		return isError
	case ':', '$', '*':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= '0' && c <= '9') || c == '-'
		})
	}

	return false
}

func getRedisError(buf []uint8) (request.DBError, bool) {
	description := strings.Trim(string(buf), "\r\n")
	errorCode := ""

	for _, redisErrorCode := range redisErrorCodes {
		if bytes.HasPrefix(buf, []byte(redisErrorCode)) {
			errorCode = strings.TrimSpace(redisErrorCode)
			break
		}
	}
	dbError := request.DBError{
		Description: description,
		ErrorCode:   errorCode,
	}
	return dbError, errorCode != ""
}

func crlfTerminatedMatch(buf []uint8, matches func(c uint8) bool) bool {
	cr := false
	i := 0
	for ; i < len(buf); i++ {
		c := buf[i]
		if matches(c) {
			continue
		}
		if c == '\r' {
			cr = true
			break
		}

		return false
	}

	if !cr || i >= len(buf)-1 {
		return false
	}

	return buf[i+1] == '\n'
}

func isValidRedisChar(c byte) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == ' ' || c == '-' || c == '_'
}

func parseRedisRequest(buf string) (string, string, bool) {
	const redisDelim = "\r\n"

	lines := util.NewSplitIterator(buf, redisDelim)

	_, eof := lines.Next()

	if eof {
		return "", "", false
	}

	// we need at least 2 lines
	if _, eof = lines.Next(); eof {
		return "", "", false
	}

	// we are good, start over
	lines.Reset()

	line, _ := lines.Next()

	// It's not a command, something else?
	if line[0] != '*' {
		return "", "", true
	}

	op := ""

	var text strings.Builder

	read := false

	for {
		line, eof = lines.Next()

		if eof {
			break
		}

		if line == redisDelim {
			continue
		}

		if !read {
			if isRedisOp([]uint8(line)) {
				read = true
			} else {
				break
			}
		} else {
			if isRedisOp([]uint8(line)) {
				text.WriteString("; ")
				continue
			}
			if !isValidRedisChar(line[0]) {
				break
			}

			trimmed := strings.TrimSuffix(line, redisDelim)

			if op == "" {
				op = trimmed
			}
			text.WriteString(trimmed)
			text.WriteString(" ")
			read = false
		}
	}

	return op, strings.TrimSpace(text.String()), true
}

func redisStatus(buf []byte) (request.DBError, int) {
	status := 0
	firstChar := buf[0]
	if firstChar != '-' {
		return request.DBError{}, status
	}
	dbError, isError := getRedisError(buf[1:])
	if isError {
		status = 1
	}

	return dbError, status
}

func TCPToRedisToSpan(trace *TCPRequestInfo, op, text string, status int, dbError request.DBError) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeRedisClient
	if trace.Direction == 0 {
		reqType = request.EventTypeRedisServer
	}

	return request.Span{
		Type:          reqType,
		Method:        op,
		Path:          text,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		DBError: dbError,
	}
}

func ReadGoRedisRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ReinterpretCast[GoRedisClientInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	peer := ""
	hostname := ""
	hostPort := 0

	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&event.Conn)).reqHostInfo()
		hostPort = int(event.Conn.D_port)
	}

	op, text, ok := parseRedisRequest(string(event.Buf[:]))

	if !ok {
		// We know it's redis request here, it just didn't complete correctly
		event.Err = 1
	}

	return request.Span{
		Type:          request.EventTypeRedisClient, // always client for Go
		Method:        op,
		Path:          text,
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(event.StartMonotimeNs),
		Start:         int64(event.StartMonotimeNs),
		End:           int64(event.EndMonotimeNs),
		Status:        int(event.Err),
		TraceID:       trace2.TraceID(event.Tp.TraceId),
		SpanID:        trace2.SpanID(event.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(event.Tp.ParentId),
		TraceFlags:    event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}
