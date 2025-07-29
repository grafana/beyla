// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"bytes"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/app/request"
)

const (
	PostgresHdrSize   = 5
	PostgresErrMinLen = PostgresHdrSize + 6

	PostgresMessageTypeQuery   = 'Q'
	PostgresMessageTypeBind    = 'B'
	PostgresMessageTypeExecute = 'E'
	PostgresMessageTypeParse   = 'P'
)

func parsePostgresMessageType(buf []uint8) uint8 {
	if len(buf) < PostgresHdrSize {
		return 0
	}
	// The first byte of the header is the message type
	return buf[0]
}

// Postgres error message contains a set of key-value fields, of which
// 3 are always present: S, C, M and the others are optional:
//
// 'E'                                                          // ErrorResponse message type
// 'S' 'ERROR' '\0'                                             // Severity
// 'C' '23505' '\0'                                             // SQLSTATE code (unique violation)
// 'M' 'duplicate key value violates unique constraint "mytable_pkey"' '\0' // Error message
// 'D' 'Key (id)=(1) already exists.' '\0'                      // Detail
// 'H' 'Perhaps you need to add a conditional statement?' '\0'  // Hint
// 'F' 'nbtinsert.c' '\0'                                       // Source file
// 'L' '402' '\0'                                               // Source line number
// 'R' '_bt_check_unique' '\0'                                  // Routine
// '\0'                                                         // End of message
func parsePostgresError(buf []uint8) *request.SQLError {
	var (
		sqlErr request.SQLError
		offset = PostgresHdrSize
		length = len(buf)
	)

	if length < PostgresErrMinLen {
		return nil // Not an error packet
	}

Loop:
	for offset < length {
		errorCode := buf[offset]
		offset++

		switch errorCode {
		case 'C': // SQLSTATE code
			sqlErr.SQLState = unix.ByteSliceToString(buf[offset : offset+6])
			offset += 6
		case 'M': // Error message
			sqlErr.Message = unix.ByteSliceToString(buf[offset:])
			offset += len(sqlErr.Message) + 1
		case 0: // End of error message
			break Loop
		default:
			// Skip uninteresting fields
			toSkip := bytes.IndexByte(buf[offset:], 0)
			if toSkip < 0 {
				return nil // Malformed error packet
			}
			offset += toSkip + 1
		}
	}

	// NOTE: As opposed to MySQL, Postgres uses the SQLSTATE standard error class,
	// defined by the SQL spec.
	// Error code will always be empty for Postgres protocol.
	if sqlErr.SQLState == "" || sqlErr.Message == "" {
		return nil
	}

	return &sqlErr
}

func postgresMessageTypeToString(messageType uint8) string {
	switch messageType {
	case PostgresMessageTypeQuery:
		return "QUERY"
	case PostgresMessageTypeBind:
		return "BIND"
	case PostgresMessageTypeExecute:
		return "EXECUTE"
	case PostgresMessageTypeParse:
		return "PARSE"
	default:
		return ""
	}
}
