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

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_init_db.html
const kMySQLInitDB = uint8(0x2)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
const kMySQLQuery = uint8(0x3)

// https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_change_user.html
const kMySQLChangeUser = uint8(0x11)

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
	hdr.length &= mysqlPayloadLengthMask
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
	length &= mysqlPayloadLengthMask
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

// skipMySQLNoResponseCommands returns the offset of the first command that is
// not a leading command without a server response, calling onClose (when not
// nil) for each statement those leading commands close. The kernel keeps such
// requests pending and appends the next command sent on the connection into
// the same event, so they can be coalesced in front of the command the
// response buffer pairs with.
func skipMySQLNoResponseCommands(buf *largebuf.LargeBuffer, onClose func(stmtID uint32)) int {
	off := 0
	for {
		length, _, ok := mysqlPacketHeader(buf, off)
		if !ok {
			return off
		}

		command, ok := mysqlByteAt(buf, off+sqlprune.MySQLHdrSize)
		if !ok || !mysqlNoResponseCommand(command) {
			return off
		}

		next := off + sqlprune.MySQLHdrSize + length
		if length == 0 || next >= buf.Len() {
			return off
		}

		if onClose != nil && command == kMySQLStmtClose && length >= 1+mysqlStatementIDSize {
			if stmtID, err := buf.U32LEAt(off + sqlprune.MySQLHdrSize + 1); err == nil {
				onClose(stmtID)
			}
		}

		off = next
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

func mysqlFirstPacket(b []byte) []byte {
	if len(b) < sqlprune.MySQLHdrSize+1 {
		return b
	}
	return b[:min(len(b), sqlprune.MySQLHdrSize+int(readMySQLHeader(b).length))]
}

func handleMySQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		op, stmt string
		tables   []string
		span     request.Span
	)

	reqOff := skipMySQLNoResponseCommands(requestBuffer, func(stmtID uint32) {
		parseCtx.mysqlPreparedStatements.Remove(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		})
	})

	if parseCtx.mysqlConns != nil && trackMySQLConnState(parseCtx, event.ConnInfo, requestBuffer, reqOff, responseBuffer) {
		return span, errIgnore
	}

	if responseBuffer.Len() < sqlprune.MySQLHdrSize+1 {
		slog.Debug("MySQL response too short")
		return span, errFallback
	}

	var cmdPacket [sqlprune.MySQLHdrSize + 1]byte
	if reqOff+len(cmdPacket) > requestBuffer.Len() || requestBuffer.CopyAt(reqOff, cmdPacket[:]) != nil {
		slog.Debug("MySQL request too short")
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMySQL, cmdPacket[:])
	sqlError := mysqlResponseError(responseBuffer)

	switch sqlCommand {
	case "STMT_PREPARE":
		if sqlError != nil {
			slog.Debug("MySQL PREPARE command errored, ignoring", "error", sqlError)
			return span, errIgnore
		}

		// On the PREPARE command, the statement ID is the first 4 bytes after the header and command ID
		// in the response buffer.
		stmtID := mysqlStatementID(responseBuffer, 0)
		if stmtID == 0 {
			slog.Debug("MySQL PREPARE command with invalid statement ID")
			return span, errFallback
		}

		_, _, stmt = detectSQL(mysqlQueryTextView(requestBuffer, reqOff))
		parseCtx.mysqlPreparedStatements.Add(mysqlPreparedStatementsKey{
			connInfo: event.ConnInfo,
			stmtID:   stmtID,
		}, stmt)

		return span, errIgnore
	case "STMT_EXECUTE":
		// On the EXECUTE command, the statement ID is the first 4 bytes after the header and command ID
		// in the request buffer.
		stmtID := mysqlStatementID(requestBuffer, reqOff)
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
		op, tables, stmt = detectSQL(mysqlQueryTextView(requestBuffer, reqOff))
	default:
		slog.Debug("MySQL command ID unhandled", "commandID", cmdPacket[sqlprune.MySQLHdrSize])
		return span, errFallback
	}

	if !validSQL(op, len(tables) > 0, request.DBMySQL) {
		slog.Debug("MySQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	span = TCPToSQLToSpan(event, op, tables, stmt, request.DBMySQL, sqlCommand, sqlError)
	setMySQLConnAttributes(parseCtx, event.ConnInfo, &span)
	return span, nil
}

// mysqlQueryTextView returns the text of the command packet at off, the only
// part of the request that is materialized.
func mysqlQueryTextView(buf *largebuf.LargeBuffer, off int) []byte {
	length, _, ok := mysqlPacketHeader(buf, off)
	textOff := off + sqlprune.MySQLHdrSize + 1
	if !ok || length == 0 || textOff > buf.Len() {
		return nil
	}

	text, err := buf.UnsafeViewAt(textOff, min(length-1, buf.Len()-textOff))
	if err != nil {
		return nil
	}
	return text
}

func mysqlStatementID(buf *largebuf.LargeBuffer, off int) uint32 {
	idOff := off + sqlprune.MySQLHdrSize + 1
	if idOff+mysqlStatementIDSize > buf.Len() {
		return 0
	}

	stmtID, err := buf.U32LEAt(idOff)
	if err != nil {
		return 0
	}
	return stmtID
}

// mysqlResponseError parses the first response packet only when it is an ERR
// packet, so other responses are never materialized.
func mysqlResponseError(resp *largebuf.LargeBuffer) *request.SQLError {
	marker, ok := mysqlByteAt(resp, sqlprune.MySQLHdrSize)
	if !ok || marker != sqlprune.MySQLErrPacketMarker {
		return nil
	}

	length, _, ok := mysqlPacketHeader(resp, 0)
	if !ok {
		return nil
	}

	packet, err := resp.UnsafeViewAt(0, min(sqlprune.MySQLHdrSize+length, resp.Len()))
	if err != nil {
		return nil
	}
	return sqlprune.SQLParseError(request.DBMySQL, packet)
}
