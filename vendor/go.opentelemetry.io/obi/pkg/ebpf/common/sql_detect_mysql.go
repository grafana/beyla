// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
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

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_send_long_data.html
const kMySQLStmtSendLongData = uint8(0x18)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_stmt_close.html
const kMySQLStmtClose = uint8(0x19)

const mysqlStatementIDSize = 4

func readMySQLHeader(b []byte) mySQLHdr {
	hdr := mySQLHdr{}

	hdr.length = binary.LittleEndian.Uint32(b[:4])
	hdr.length &= 0x00ffffff // remove the sequence id from the length
	hdr.command = b[4]

	return hdr
}

func isMySQL(b *largebuf.LargeBuffer) bool {
	// 4-byte header (3-byte length + 1-byte sequence ID) + command byte + at least 1 payload byte
	if b.Len() < 6 {
		return false
	}

	length, err := b.U32LEAt(0)
	if err != nil {
		return false
	}
	length &= 0x00ffffff // remove the sequence id from the length
	if length == 0 {
		return false
	}
	command, err := b.U8At(4)
	if err != nil {
		return false
	}

	return command == kMySQLQuery || command == kMySQLPrepare || command == kMySQLExecute
}

func mysqlNoResponseCommand(command uint8) bool {
	return command == kMySQLStmtSendLongData || command == kMySQLStmtClose
}

// skipMySQLNoResponseCommands advances past leading commands without a server
// response. The kernel keeps such requests pending and appends the next
// command sent on the connection into the same event, so they can be coalesced
// in front of the command the response buffer pairs with.
func skipMySQLNoResponseCommands(reqRaw []byte) ([]byte, []uint32) {
	var closedStmtIDs []uint32

	for {
		if len(reqRaw) < sqlprune.MySQLHdrSize+1 {
			return reqRaw, closedStmtIDs
		}

		hdr := readMySQLHeader(reqRaw)
		if !mysqlNoResponseCommand(hdr.command) {
			return reqRaw, closedStmtIDs
		}

		packetLen := sqlprune.MySQLHdrSize + int(hdr.length)
		if packetLen <= sqlprune.MySQLHdrSize || packetLen >= len(reqRaw) {
			return reqRaw, closedStmtIDs
		}

		if hdr.command == kMySQLStmtClose && hdr.length >= 1+mysqlStatementIDSize {
			stmtIDOffset := sqlprune.MySQLHdrSize + 1
			closedStmtIDs = append(closedStmtIDs, binary.LittleEndian.Uint32(reqRaw[stmtIDOffset:stmtIDOffset+mysqlStatementIDSize]))
		}

		reqRaw = reqRaw[packetLen:]
	}
}

func mysqlPreparedStatements(b []byte) (string, string, string) {
	execIdx := asciiIndexFold(b, sqlExecuteKeyword)
	if execIdx < 0 {
		return "", "", ""
	}

	text := string(b[execIdx:])
	parts := strings.Split(text, " ")
	op := parts[0]
	var table string
	if len(parts) > 1 {
		table = parts[1]
	}

	return op, table, text
}

func handleMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		op, stmt string
		tables   []string
		span     request.Span
	)

	if responseBuffer.Len() < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL response too short")
		return span, errFallback
	}
	reqRaw := requestBuffer.UnsafeView()
	respRaw := responseBuffer.UnsafeView()

	// Commands without a server response (e.g. COM_STMT_CLOSE) stay pending in
	// the kernel, which appends the next command sent on the connection into
	// the same event. Skip them so the command paired with the response is the
	// one parsed below.
	reqRaw, closedStmtIDs := skipMySQLNoResponseCommands(reqRaw)
	for _, stmtID := range closedStmtIDs {
		parseCtx.mysqlPreparedStatements.Remove(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
	}
	if len(reqRaw) < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL request too short")
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, reqRaw)
	sqlError := sqlprune.SQLParseError(request.DBMySQL, respRaw)

	switch sqlCommand {
	case "STMT_PREPARE":
		if sqlError != nil {
			slog.Debug("MySQL PREPARE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the PREPARE command, the statement ID is the first 4 bytes after the header and command ID
		// in the response buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, respRaw)
		if stmtID == 0 {
			slog.Debug("MySQL PREPARE command with invalid statement ID")
			return span, errFallback
		}

		_, _, stmt = detectSQL(reqRaw[sqlprune.MySQLHdrSize+1:])
		parseCtx.mysqlPreparedStatements.Add(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		}, stmt)

		return span, errIgnore
	case "STMT_EXECUTE":
		// On the EXECUTE command, the statement ID is the first 4 bytes after the header and command ID
		// in the request buffer.
		stmtID := sqlprune.SQLParseStatementID(request.DBMySQL, reqRaw)
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
		op, tables = sqlprune.SQLParseOperationAndTables(stmt)
	case "QUERY":
		op, tables, stmt = detectSQL(reqRaw[sqlprune.MySQLHdrSize+1:])
	default:
		slog.Debug("MySQL command ID unhandled", "commandID", reqRaw[sqlprune.MySQLHdrSize])
		return span, errFallback
	}

	if !validSQL(op, len(tables) > 0, request.DBMySQL) {
		slog.Debug("MySQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, tables, stmt, request.DBMySQL, sqlCommand, sqlError), nil
}
