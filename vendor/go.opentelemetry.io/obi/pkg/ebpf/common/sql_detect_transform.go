// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

func sqlKind(b []byte) request.SQLKind {
	if isPostgres(b) {
		return request.DBPostgres
	} else if isMySQL(b) {
		return request.DBMySQL
	}

	return request.DBGeneric
}

// If we have already identified Postgres or MySQL, allow the SQL
// command to be valid with just operation, e.g. we didn't find the
// table. Otherwise, be more picky so that we don't misclassify easily
// traffic that may have SQL like keywords as SQL.
func validSQL(op, table string, sqlKind request.SQLKind) bool {
	return op != "" && (sqlKind != request.DBGeneric || table != "")
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

func detectSQLPayload(useHeuristics bool, b []byte) (string, string, string, request.SQLKind) {
	sqlKind := sqlKind(b)
	if !useHeuristics {
		if sqlKind == request.DBGeneric {
			return "", "", "", sqlKind
		}
	}
	op, table, sql := detectSQL(string(b))
	if !validSQL(op, table, sqlKind) {
		switch sqlKind {
		case request.DBPostgres:
			op, table, sql = postgresPreparedStatements(b)
		case request.DBMySQL:
			op, table, sql = mysqlPreparedStatements(b)
		}
	}

	return op, table, sql, sqlKind
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

func TCPToSQLToSpan(trace *TCPRequestInfo, op, table, sql string, kind request.SQLKind, sqlCommand string, sqlError *request.SQLError) request.Span {
	var (
		peer, hostname             string
		peerPort, hostPort, status int
	)

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(&trace.ConnInfo).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	if sqlError != nil {
		status = 1
	}

	return request.Span{
		Type:          request.EventTypeSQLClient,
		Method:        op,
		Path:          table,
		Peer:          peer,
		PeerPort:      peerPort,
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: int64(trace.ReqLen),
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        status,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		Statement:  sql,
		SubType:    int(kind),
		SQLCommand: sqlCommand,
		SQLError:   sqlError,
	}
}
