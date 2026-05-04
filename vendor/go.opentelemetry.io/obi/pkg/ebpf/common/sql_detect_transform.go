// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

func sqlKind(b *largebuf.LargeBuffer) request.SQLKind {
	if isPostgres(b) {
		return request.DBPostgres
	}
	if isMySQL(b) {
		return request.DBMySQL
	}
	if isMSSQL(b) {
		return request.DBMSSQL
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

func toLowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

// equalFoldASCII reports whether a and b are equal under ASCII case-folding.
func equalFoldASCII(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca := toLowerASCII(a[i])
		cb := toLowerASCII(b[i])
		if ca != cb {
			return false
		}
	}
	return true
}

// asciiIndexFold returns the index of the first occurrence of substr in s,
// matching ASCII letters case-insensitively. Returns -1 if not found.
func asciiIndexFold(s, substr []byte) int {
	n := len(substr)
	if n == 0 || len(s) < n {
		return -1
	}
	for i := 0; i <= len(s)-n; i++ {
		if equalFoldASCII(s[i:i+n], substr) {
			return i
		}
	}
	return -1
}

var sqlKeywords = [][]byte{
	[]byte("SELECT"), []byte("UPDATE"), []byte("DELETE"),
	[]byte("INSERT"), []byte("ALTER"), []byte("CREATE"), []byte("DROP"),
}

var sqlExecuteKeyword = []byte("EXECUTE ")

func detectSQLPayload(useHeuristics bool, b *largebuf.LargeBuffer) (string, string, string, request.SQLKind) {
	sqlKind := sqlKind(b)

	if !useHeuristics && sqlKind == request.DBGeneric {
		return "", "", "", sqlKind
	}

	view := b.UnsafeView()

	op, table, sql := detectSQL(view)

	if !validSQL(op, table, sqlKind) {
		switch sqlKind {
		case request.DBPostgres:
			op, table, sql = postgresPreparedStatements(b)
		case request.DBMySQL:
			op, table, sql = mysqlPreparedStatements(view)
		case request.DBMSSQL:
			op, table, sql = mssqlExtractBatchSQL(b)
		}
	}

	return op, table, sql, sqlKind
}

func detectSQL(buf []byte) (string, string, string) {
	minIdx := -1
	for _, q := range sqlKeywords {
		i := asciiIndexFold(buf, q)
		if i >= 0 && (minIdx < 0 || i < minIdx) {
			minIdx = i
		}
	}

	if minIdx >= 0 {
		sql := cstr(buf[minIdx:])
		op, table := sqlprune.SQLParseOperationAndTable(sql)
		return op, table, sql
	}

	return "", "", ""
}

func TCPToSQLToSpan(trace *TCPRequestInfo, op, table, sql string, kind request.SQLKind, sqlCommand string, sqlError *request.SQLError) request.Span {
	var (
		peer, hostname             string
		peerPort, hostPort, status int
	)
	spanType := request.EventTypeSQLClient
	if trace.IsServer {
		spanType = request.EventTypeSQLServer
	}

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(&trace.ConnInfo).reqHostInfo()
		peerPort = int(trace.ConnInfo.S_port)
		hostPort = int(trace.ConnInfo.D_port)
	}

	if sqlError != nil {
		status = 1
	}

	return request.Span{
		Type:          spanType,
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
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		Statement:  sql,
		SubType:    int(kind),
		SQLCommand: sqlCommand,
		SQLError:   sqlError,
	}
}
