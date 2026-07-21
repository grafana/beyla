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
func validSQL(op string, hasTables bool, sqlKind request.SQLKind) bool {
	return op != "" && (sqlKind != request.DBGeneric || hasTables)
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

const minSQLPrintableRun = len("SELECT 1")

// isSQLByte reports whether b is a byte that can appear inside a SQL statement
// (printable ASCII plus the common whitespace characters).
func isSQLByte(b byte) bool {
	return (b >= 0x20 && b < 0x7f) || b == '\t' || b == '\n' || b == '\r'
}

// firstSQLRun returns the start index of the first contiguous run of at least
// minLen SQL-plausible bytes in buf, or -1 if no such run exists.
func firstSQLRun(buf []byte, minLen int) int {
	if len(buf) < minLen {
		return -1
	}
	run := 0
	for i, b := range buf {
		if isSQLByte(b) {
			run++
			if run >= minLen {
				return i - minLen + 1
			}
		} else {
			run = 0
		}
	}
	return -1
}

func detectSQLPayload(useHeuristics bool, b *largebuf.LargeBuffer) (string, []string, string, request.SQLKind) {
	sqlKind := sqlKind(b)

	if !useHeuristics && sqlKind == request.DBGeneric {
		return "", nil, "", sqlKind
	}

	view := b.UnsafeView()

	op, tables, sql := detectSQL(view)

	if !validSQL(op, len(tables) > 0, sqlKind) {
		var table string
		switch sqlKind {
		case request.DBPostgres:
			op, table, sql = postgresPreparedStatements(b)
		case request.DBMySQL:
			op, table, sql = mysqlPreparedStatements(view)
		case request.DBMSSQL:
			op, tables, sql = mssqlExtractBatchSQL(b)
			return op, tables, sql, sqlKind
		}
		tables = nil
		if table != "" {
			tables = []string{table}
		}
	}

	return op, tables, sql, sqlKind
}

func detectSQL(buf []byte) (string, []string, string) {
	// Cheap prefilter: most SQL wire protocols carry a small binary header
	// followed by the statement as plain text. If no printable-ASCII run long
	// enough to fit the shortest valid SQL exists, skip the case-fold scan.
	start := firstSQLRun(buf, minSQLPrintableRun)
	if start < 0 {
		return "", nil, ""
	}
	scan := buf[start:]

	minIdx := -1
	for _, q := range sqlKeywords {
		i := asciiIndexFold(scan, q)
		if i >= 0 && (minIdx < 0 || i < minIdx) {
			minIdx = i
		}
	}

	if minIdx >= 0 {
		sql := cstr(scan[minIdx:])
		op, tables := sqlprune.SQLParseOperationAndTables(sql)
		return op, tables, sql
	}

	return "", nil, ""
}

func TCPToSQLToSpan(trace *TCPRequestInfo, op string, tables []string, sql string, kind request.SQLKind, sqlCommand string, sqlError *request.SQLError) request.Span {
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
		Path:          sqlprune.SQLTargetCollection(op, tables),
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
		Statement:      sql,
		SubType:        int(kind),
		SQLCommand:     sqlCommand,
		SQLError:       sqlError,
		DBQuerySummary: sqlprune.SQLQuerySummary(op, tables),
	}
}
