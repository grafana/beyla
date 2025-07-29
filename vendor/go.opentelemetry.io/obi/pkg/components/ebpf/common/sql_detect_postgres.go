// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/sqlprune"
)

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
		for j := 0; j < argLen; j++ {
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

func handlePostgres(_ *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, error) {
	var (
		op, table, stmt string
		span            request.Span
	)

	if len(requestBuffer) < sqlprune.PostgresHdrSize+1 {
		slog.Warn("Postgres request too short")
		return span, errFallback
	}
	if len(responseBuffer) < sqlprune.PostgresHdrSize+1 {
		slog.Warn("Postgres response too short")
		return span, errFallback
	}

	sqlCommand := sqlprune.SQLParseCommandID(request.DBPostgres, requestBuffer)
	sqlError := sqlprune.SQLParseError(request.DBPostgres, responseBuffer)

	switch sqlCommand {
	// TODO(matt): prepared statements
	case "QUERY":
		op, table, stmt = detectSQL(string(requestBuffer[sqlprune.PostgresHdrSize:]))
	default:
		slog.Warn("Postgres message type unhandled", "messageType", requestBuffer[sqlprune.PostgresHdrSize])
		return span, errFallback
	}

	if !validSQL(op, table, request.DBPostgres) {
		slog.Warn("Postgres operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBPostgres, sqlCommand, sqlError), nil
}
