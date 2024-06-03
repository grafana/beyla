package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"
	trace2 "go.opentelemetry.io/otel/trace"
	"golang.org/x/net/http2"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/sqlprune"
)

func ReadTCPRequestIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event TCPRequestInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	b := event.Buf[:]

	l := int(event.Len)
	if l < 0 || len(b) < l {
		l = len(b)
	}

	buf := string(event.Buf[:l])

	// Check if we have a SQL statement
	op, table, sql := detectSQL(buf)
	switch {
	case validSQL(op, table):
		return TCPToSQLToSpan(&event, op, table, sql), false, nil
	case isHTTP2(b, &event):
		MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &event}
	case isRedis(event.Buf[:l]) && isRedis(event.Rbuf[:]):
		op, text, ok := parseRedisRequest(buf)

		if ok {
			status := 0
			if isErr := isRedisError(event.Rbuf[:]); isErr {
				status = 1
			}

			return TCPToRedisToSpan(&event, op, text, status), false, nil
		}
	default:
		k, err := ProcessPossibleKafkaEvent(b, event.Rbuf[:])
		if err == nil {
			return TCPToKafkaToSpan(&event, k), false, nil
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func validSQL(op, table string) bool {
	return op != "" && table != ""
}

func detectSQL(buf string) (string, string, string) {
	b := asciiToUpper(buf)
	for _, q := range []string{"SELECT", "UPDATE", "DELETE", "INSERT", "ALTER", "CREATE", "DROP"} {
		i := strings.Index(b, q)
		if i >= 0 {
			sql := cstr([]uint8(b[i:]))

			op, table := sqlprune.SQLParseOperationAndTable(sql)
			return op, table, sql
		}
	}

	return "", "", ""
}

// when the input string is invalid unicode (might happen with the ringbuffer
// data), strings.ToUpper might return a string larger than the input string,
// and might cause some later out of bound errors.
func asciiToUpper(input string) string {
	out := make([]byte, len(input))
	for i := range input {
		if input[i] >= 'a' && input[i] <= 'z' {
			out[i] = input[i] - byte('a') + byte('A')
		} else {
			out[i] = input[i]
		}
	}
	return string(out)
}

func (trace *TCPRequestInfo) reqHostInfo() (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, trace.ConnInfo.S_addr[:])
	copy(dst, trace.ConnInfo.D_addr[:])

	return src.String(), dst.String()
}

func TCPToSQLToSpan(trace *TCPRequestInfo, op, table, sql string) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = trace.reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:          request.EventTypeSQLClient,
		Method:        op,
		Path:          table,
		Peer:          peer,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace2.TraceID(trace.Tp.TraceId),
		SpanID:        trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:  trace2.SpanID(trace.Tp.ParentId),
		Flags:         trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		Statement: sql,
	}
}

func isHTTP2(data []uint8, event *TCPRequestInfo) bool {
	framer := byteFramer(data)

	for {
		f, err := framer.ReadFrame()

		if err != nil {
			break
		}

		if ff, ok := f.(*http2.HeadersFrame); ok {
			method, path, _ := readMetaFrame((*BPFConnInfo)(&event.ConnInfo), framer, ff)
			return method != "" || path != ""
		}
	}

	return false
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = trace.reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}
	return request.Span{
		Type:           request.EventTypeKafkaClient,
		Method:         data.Operation.String(),
		OtherNamespace: data.ClientID,
		Path:           data.Topic,
		Peer:           peer,
		Host:           hostname,
		HostPort:       hostPort,
		ContentLength:  0,
		RequestStart:   int64(trace.StartMonotimeNs),
		Start:          int64(trace.StartMonotimeNs),
		End:            int64(trace.EndMonotimeNs),
		Status:         0,
		TraceID:        trace2.TraceID(trace.Tp.TraceId),
		SpanID:         trace2.SpanID(trace.Tp.SpanId),
		ParentSpanID:   trace2.SpanID(trace.Tp.ParentId),
		Flags:          trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
	}
}
