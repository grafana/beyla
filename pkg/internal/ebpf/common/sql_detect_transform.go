package ebpfcommon

import (
	"strings"

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
