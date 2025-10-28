// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type postgresPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtName string
}

type postgresPortalsKey struct {
	connInfo   BpfConnectionInfoT
	portalName string
}

const (
	kPostgresBind    = byte('B')
	kPostgresQuery   = byte('Q')
	kPostgresCommand = byte('C')
)

func isPostgres(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery || op == kPostgresCommand || op == kPostgresBind)
}

func isPostgresBindCommand(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresBind)
}

func isPostgresQueryCommand(b []byte) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery)
}

func isValidPostgresPayload(b []byte) (byte, bool) {
	// https://github.com/postgres/postgres/blob/master/src/interfaces/libpq/fe-protocol3.c#L97
	if len(b) < 5 {
		return 0, false
	}

	size := int32(binary.BigEndian.Uint32(b[1:5]))
	if size < 0 || size > 3000 {
		return 0, false
	}

	return b[0], true
}

//nolint:cyclop
func parsePostgresBindCommand(buf []byte) (string, string, []string, error) {
	statement := []byte{}
	portal := []byte{}
	args := []string{}

	size := min(int(binary.BigEndian.Uint32(buf[1:5])), len(buf))
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

	if ptr+2 >= size {
		return string(statement), string(portal), args, errors.New("too short, while parsing format codes")
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
		for range argLen {
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
	size := min(int(binary.BigEndian.Uint32(buf[1:5])), len(buf))
	ptr := 5

	if ptr > size {
		return "", errors.New("too short")
	}

	return string(buf[ptr:size]), nil
}

func postgresPreparedStatements(b []byte) (string, string, string) {
	var op, table, sql string
	if isPostgresBindCommand(b) {
		statement, portal, args, err := parsePostgresBindCommand(b)
		if err == nil {
			op = "PREPARED STATEMENT"
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

	return op, table, sql
}

type postgresMessage struct {
	typ  string
	data []byte
}

type postgresMessageIterator struct {
	buf []byte
	err error
	eof bool
}

func (it *postgresMessageIterator) isEOF() bool {
	return it.eof
}

func (it *postgresMessageIterator) next() (msg postgresMessage) {
	if it.err != nil || len(it.buf) == 0 {
		it.eof = true
		return
	}
	if len(it.buf) < sqlprune.PostgresHdrSize {
		it.err = errors.New("remaining buffer too short for message header")
		return
	}

	msgType := sqlprune.SQLParseCommandID(request.DBPostgres, it.buf)
	it.buf = it.buf[1:]
	size := int32(binary.BigEndian.Uint32(it.buf[:4]))
	it.buf = it.buf[4:]

	if size < sqlprune.PostgresHdrSize-1 {
		it.err = errors.New("malformed Postgres message")
		return
	}

	payloadSize := size - sqlprune.PostgresHdrSize + 1
	if len(it.buf) < int(payloadSize) {
		it.err = fmt.Errorf("remaining buffer too short for message data: expected %d bytes, got %d", payloadSize, len(it.buf))
		return
	}

	data := it.buf[:payloadSize]
	it.buf = it.buf[payloadSize:]

	msg = postgresMessage{typ: msgType, data: data}
	return
}

func handlePostgres(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var (
		hasSpan         bool
		op, table, stmt string
		span            request.Span
	)

	if len(requestBuffer) < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres request too short")
		return span, errFallback
	}
	if len(responseBuffer) < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres response too short")
		return span, errFallback
	}

	var (
		msg      postgresMessage
		it       = &postgresMessageIterator{buf: requestBuffer}
		sqlError = sqlprune.SQLParseError(request.DBPostgres, responseBuffer)
	)

Loop:
	for {
		if msg = it.next(); it.isEOF() {
			break
		}
		if it.err != nil {
			slog.Debug("failed to parse Postgres request messages", "error", it.err)
			return span, errFallback
		}

		switch msg.typ {
		case "QUERY":
			op, table, stmt = detectSQL(string(msg.data))
			hasSpan = true
			break Loop
		case "PARSE":
			// On the PARSE command, the statement name is the first 4 bytes after the header and command ID
			// in the request buffer.
			stmtName := unix.ByteSliceToString(msg.data)
			stmtNameLen := len(stmtName)
			_, _, stmt = detectSQL(string(msg.data[stmtNameLen:]))

			parseCtx.postgresPreparedStatements.Add(postgresPreparedStatementsKey{
				connInfo: event.ConnInfo,
				stmtName: stmtName,
			}, stmt)

			continue
		case "BIND":
			portal := unix.ByteSliceToString(msg.data)
			portalLen := len(portal) + 1 // +1 for the null terminator
			stmtName := unix.ByteSliceToString(msg.data[portalLen:])

			parseCtx.postgresPortals.Add(postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: portal,
			}, stmtName)

			continue
		case "EXECUTE":
			portalKey := postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: unix.ByteSliceToString(msg.data),
			}

			stmtName, found := parseCtx.postgresPortals.Get(portalKey)
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown portal", "portal", portalKey.portalName)
				continue
			}

			preparedStmtKey := postgresPreparedStatementsKey{
				connInfo: event.ConnInfo,
				stmtName: stmtName,
			}

			stmt, found = parseCtx.postgresPreparedStatements.Get(preparedStmtKey)
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown statement", "stmtName", stmtName)
				continue
			}

			op, table = sqlprune.SQLParseOperationAndTable(stmt)
			hasSpan = true
			break Loop
		default:
			continue
		}
	}

	if !hasSpan {
		return span, errIgnore
	}

	if !validSQL(op, table, request.DBPostgres) {
		// This can happen for stuff like 'BEGIN', etc.
		slog.Debug("Postgres operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBPostgres, msg.typ, sqlError), nil
}
