// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type mysqlPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtID   uint32
}

type mySQLHdr struct {
	length  uint32 // payload length + sequence ID
	command uint8  // command type
}

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
const kMySQLQuery = uint8(0x3)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_prepare.html
const kMySQLPrepare = uint8(0x16)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_execute.html
const kMySQLExecute = uint8(0x17)

func isMySQL(b []byte) bool {
	return isValidMySQLPayload(b)
}

func readMySQLHeader(b []byte) mySQLHdr {
	hdr := mySQLHdr{}

	hdr.length = binary.LittleEndian.Uint32(b[:4])
	hdr.length &= 0x00ffffff // remove the sequence id from the length
	hdr.command = b[4]

	return hdr
}

func isValidMySQLPayload(b []byte) bool {
	// the header is at least 5 bytes
	if len(b) < 6 {
		return false
	}

	hdr := readMySQLHeader(b)
	if hdr.length == 0 {
		return false
	}

	return hdr.command == kMySQLQuery || hdr.command == kMySQLPrepare || hdr.command == kMySQLExecute
}

func mysqlPreparedStatements(b []byte) (string, string, string) {
	text := string(b)
	query := asciiToUpper(text)
	execIdx := strings.Index(query, "EXECUTE ")
	if execIdx < 0 {
		return "", "", ""
	}

	if execIdx >= len(text) {
		return "", "", ""
	}

	text = text[execIdx:]

	parts := strings.Split(text, " ")
	op := parts[0]
	var table string
	if len(parts) > 1 {
		table = parts[1]
	}
	sql := text

	return op, table, sql
}

func handleMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var (
		op, table, stmt string
		span            request.Span
	)

	if len(requestBuffer) < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL request too short")
		return span, errFallback
	}
	if len(responseBuffer) < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL response too short")
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, requestBuffer)
	sqlError := sqlprune.SQLParseError(request.DBMySQL, responseBuffer)

	switch sqlCommand {
	case "STMT_PREPARE":
		if sqlError != nil {
			slog.Debug("MySQL PREPARE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the PREPARE command, the statement ID is the first 4 bytes after the header and command ID
		// in the response buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, responseBuffer)
		if stmtID == 0 {
			slog.Debug("MySQL PREPARE command with invalid statement ID")
			return span, errFallback
		}

		_, _, stmt = detectSQL(string(requestBuffer[sqlprune.MySQLHdrSize+1:]))
		parseCtx.mysqlPreparedStatements.Add(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		}, stmt)

		return span, errIgnore
	case "STMT_EXECUTE":
		// On the EXECUTE command, the statement ID is the first 4 bytes after the header and command ID
		// in the request buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, requestBuffer)
		if stmtID == 0 {
			slog.Debug("MySQL EXECUTE command with invalid statement ID")
			return span, errFallback
		}

		var found bool
		stmt, found = parseCtx.mysqlPreparedStatements.Get(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
		if !found {
			slog.Debug("MySQL EXECUTE command with unknown statement ID", "stmtID", stmtID)
			return span, errFallback
		}
		op, table = sqlprune.SQLParseOperationAndTable(stmt)
	case "QUERY":
		op, table, stmt = detectSQL(string(requestBuffer[sqlprune.MySQLHdrSize+1:]))
	default:
		slog.Debug("MySQL command ID unhandled", "commandID", requestBuffer[sqlprune.MySQLHdrSize])
		return span, errFallback
	}

	if !validSQL(op, table, request.DBMySQL) {
		slog.Debug("MySQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMySQL, sqlCommand, sqlError), nil
}
