package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/sqlprune"
)

func validSQL(op, table string) bool {
	return op != "" && table != ""
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

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == ' ' || c == '-' {
			continue
		}
		return false
	}

	return true
}

func detectSQLBytes(b []byte) (string, string, string) {
	op, table, sql := detectSQL(string(b))
	if !validSQL(op, table) {
		if isPostgresBindCommand(b) {
			statement, portal, args, err := parsePostgresBindCommand(b)
			if err == nil {
				op = "BIND"
				table = fmt.Sprintf("%s.%s", statement, portal)
				for _, arg := range args {
					if isASCII(arg) {
						sql += arg + " "
					}
				}
			}
		} else if isPostgresQueryCommand(b) {
			text, err := parsePosgresQueryCommand(b)
			if err == nil {
				query := asciiToUpper(text)
				if strings.HasPrefix(query, "EXECUTE ") {
					parts := strings.Split(text, " ")
					op = parts[0]
					if len(parts) > 1 {
						table = parts[1]
					}
					sql = text
				}
			}
		}
	}

	return op, table, sql
}

func detectSQL(buf string) (string, string, string) {
	b := asciiToUpper(buf)
	for _, q := range []string{"SELECT", "UPDATE", "DELETE", "INSERT", "ALTER", "CREATE", "DROP"} {
		i := strings.Index(b, q)
		if i >= 0 {
			sql := cstr([]uint8(buf[i:]))

			op, table := sqlprune.SQLParseOperationAndTable(sql)
			return op, table, sql
		}
	}

	return "", "", ""
}

func isPostgresBindCommand(b []byte) bool {
	return isPostgresCommand('B', b)
}

func isPostgresQueryCommand(b []byte) bool {
	return isPostgresCommand('Q', b)
}

func isPostgresCommand(lookup byte, b []byte) bool {
	if len(b) < 5 {
		return false
	}

	if b[0] == lookup {
		size := int32(binary.BigEndian.Uint32(b[1:5]))
		if size < 0 || size > 1000 {
			return false
		}
		return true
	}

	return false
}

// nolint:cyclop
func parsePostgresBindCommand(buf []byte) (string, string, []string, error) {
	statement := []byte{}
	portal := []byte{}
	args := []string{}

	size := int(binary.BigEndian.Uint32(buf[1:5]))
	if size > len(buf) {
		size = len(buf)
	}
	ptr := 5

	// parse statement, zero terminated string
	for {
		if ptr >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing statement")
		}
		b := buf[ptr]
		ptr++

		if b == 0 {
			break
		}
		statement = append(statement, b)
	}

	// parse portal, zero terminated string
	for {
		if ptr >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing portal")
		}
		b := buf[ptr]
		ptr++

		if b == 0 {
			break
		}
		portal = append(portal, b)
	}

	if ptr+2 >= size {
		return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
	}

	formats := int16(binary.BigEndian.Uint16(buf[ptr : ptr+2]))
	ptr += 2
	for i := 0; i < int(formats); i++ {
		// ignore format codes
		if ptr+2 >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
		}
		ptr += 2
	}

	params := int16(binary.BigEndian.Uint16(buf[ptr : ptr+2]))
	ptr += 2
	for i := 0; i < int(params); i++ {
		if ptr+4 >= size {
			return string(statement), string(portal), args, errors.New("too short, while parsing params")
		}
		argLen := int(binary.BigEndian.Uint32(buf[ptr : ptr+4]))
		ptr += 4
		arg := []byte{}
		for j := 0; j < int(argLen); j++ {
			if ptr >= size {
				break
			}
			arg = append(arg, buf[ptr])
			ptr++
		}
		args = append(args, string(arg))
	}

	return string(statement), string(portal), args, nil
}

func parsePosgresQueryCommand(buf []byte) (string, error) {
	size := int(binary.BigEndian.Uint32(buf[1:5]))
	if size > len(buf) {
		size = len(buf)
	}
	ptr := 5

	if ptr > size {
		return "", errors.New("too short")
	}

	return string(buf[ptr:size]), nil
}

func TCPToSQLToSpan(trace *TCPRequestInfo, op, table, sql string) request.Span {
	peer := ""
	peerPort := 0
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:          request.EventTypeSQLClient,
		Method:        op,
		Path:          table,
		Peer:          peer,
		PeerPort:      peerPort,
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
