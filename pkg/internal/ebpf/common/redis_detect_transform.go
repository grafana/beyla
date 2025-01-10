package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
)

const minRedisFrameLen = 3

func isRedis(buf []uint8) bool {
	if len(buf) < minRedisFrameLen {
		return false
	}

	return isRedisOp(buf)
}

// nolint:cyclop
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
		return isRedisError(buf[1:])
	case ':', '$', '*':
		return crlfTerminatedMatch(buf[1:], func(c uint8) bool {
			return (c >= '0' && c <= '9') || c == '-'
		})
	}

	return false
}

func isRedisError(buf []uint8) bool {
	return bytes.HasPrefix(buf, []byte("ERR ")) ||
		bytes.HasPrefix(buf, []byte("WRONGTYPE ")) ||
		bytes.HasPrefix(buf, []byte("MOVED ")) ||
		bytes.HasPrefix(buf, []byte("ASK ")) ||
		bytes.HasPrefix(buf, []byte("BUSY ")) ||
		bytes.HasPrefix(buf, []byte("NOSCRIPT ")) ||
		bytes.HasPrefix(buf, []byte("CLUSTERDOWN "))
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
	lines := strings.Split(buf, "\r\n")

	if len(lines) < 2 || len(lines[0]) == 0 {
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
		if len(l) == 0 {
			continue
		}
		if !read {
			if isRedisOp([]uint8(l + "\r\n")) {
				read = true
			} else {
				break
			}
		} else {
			if isRedisOp([]uint8(l + "\r\n")) {
				text += "; "
				continue
			}
			if !isValidRedisChar(l[0]) {
				break
			}
			if op == "" {
				op = l
			}
			text += l + " "
			read = false
		}
	}

	return op, text, true
}

func redisStatus(buf []byte) int {
	status := 0
	if isErr := isRedisError(buf); isErr {
		status = 1
	}

	return status
}

func TCPToRedisToSpan(trace *TCPRequestInfo, op, text string, status int) request.Span {
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
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}

func ReadGoRedisRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event GoRedisClientInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
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
		Flags:         event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
	}, false, nil
}
