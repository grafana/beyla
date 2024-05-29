package ebpfcommon

import (
	"bytes"
	"strings"

	"github.com/grafana/beyla/pkg/internal/request"
	trace2 "go.opentelemetry.io/otel/trace"
)

const minRedisFrameLen = 3

func isRedis(buf []uint8) bool {
	if len(buf) < minRedisFrameLen {
		return false
	}

	c := buf[0]

	switch c {
	case '+':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '.' || c == ' ' || c == '-' || c == '_'
		})
	case '-':
		return isRedisError(buf[1:])
	case ':', '$', '*':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= '0' && c <= '1')
		})
	}

	return false
}

func isRedisError(buf []uint8) bool {
	return bytes.HasPrefix(buf, []byte("ERR ")) || bytes.HasPrefix(buf, []byte("WRONGTYPE "))
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

func parseRedisRequest(buf string) (string, string, bool) {
	lines := strings.Split(buf, "\r\n")

	if len(lines) < 1 {
		return "", "", false
	}

	// It's not a command, something else?
	if lines[0][0] != '*' {
		return "", "", true
	}

	op := ""
	text := ""

	read := false
	// Skip the first line
	for _, l := range lines[1:] {
		if !read {
			if isRedis([]uint8(l)) {
				read = true
			} else {
				break
			}
		} else {
			if op == "" {
				op = l
			}
			text += l + " "
			read = false
		}
	}

	return op, text, true
}

func TCPToRedisToSpan(trace *TCPRequestInfo, op, text string, status int) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = trace.reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:          request.EventTypeRedisClient,
		Method:        op,
		Path:          text,
		Peer:          peer,
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
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
