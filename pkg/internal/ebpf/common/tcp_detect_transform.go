package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/request"
)

// nolint:cyclop
func ReadTCPRequestIntoSpan(record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	var event TCPRequestInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
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

	b := event.Buf[:l]

	buf := string(b)

	// Check if we have a SQL statement
	op, table, sql := detectSQL(buf)
	switch {
	case validSQL(op, table):
		return TCPToSQLToSpan(&event, op, table, sql), false, nil
	case isRedis(b) && isRedis(event.Rbuf[:]):
		op, text, ok := parseRedisRequest(buf)

		if ok {

			if strings.Contains(text, "$") {
				fmt.Printf("** BAD ** %s %v\n", text, event.Buf[:])
			}

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
		} else if isHTTP2(b, &event) {
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &event}
		}
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

func (connInfo *BPFConnInfo) reqHostInfo() (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, connInfo.S_addr[:])
	copy(dst, connInfo.D_addr[:])

	return src.String(), dst.String()
}
