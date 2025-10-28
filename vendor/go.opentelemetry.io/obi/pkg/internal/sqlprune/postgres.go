// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"bytes"
	"encoding/binary"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	PostgresHdrSize = 5 // 'E' + Int32(len)

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
// 'E'                                                                       // ErrorResponse message type
// Int32(len)                                                                // Message len (including self)
// 'S' 'ERROR' '\0'                                                          // Severity
// 'C' '23505' '\0'                                                          // SQLSTATE code (unique violation)
// 'M' 'duplicate key value violates unique constraint "mytable_pkey"' '\0'  // Error message
// 'D' 'Key (id)=(1) already exists.' '\0'                                   // Detail
// 'H' 'Perhaps you need to add a conditional statement?' '\0'               // Hint
// 'F' 'nbtinsert.c' '\0'                                                    // Source file
// 'L' '402' '\0'                                                            // Source line number
// 'R' '_bt_check_unique' '\0'                                               // Routine
// '\0'                                                                      // End of message

// +--------+----------------+-----------------------------------+
// | 'E'    | int32 length   | fields... 0x00 terminator         |
// +--------+----------------+-----------------------------------+
//
// fields:
// +------------+--------------------+
// | 1 byte     | field code         |
// | C-string   | field value        |
// +------------+--------------------+
// (repeat until final 0x00)
func parsePostgresError(buf []uint8) *request.SQLError {
	var sqlErr request.SQLError

	if len(buf) < PostgresHdrSize {
		return nil // Not an error packet
	}

	if buf[0] != 'E' {
		return nil
	}

	// consume
	buf = buf[1:]

	// includes its own 4 bytes, excludes 'E'
	msgLen := int(binary.BigEndian.Uint32(buf[0:4]))

	if msgLen < 4 || msgLen > len(buf) {
		return nil
	}

	payloadLen := msgLen - 4

	if payloadLen <= 0 {
		return nil
	}

	payload := buf[4:]

	if payloadLen > len(payload) {
		return nil
	}

	for i := 0; i < payloadLen; {
		errorCode := payload[i]

		// end of message
		if errorCode == 0 {
			break
		}

		i++

		j := bytes.IndexByte(payload[i:], 0)

		if j < 0 {
			return nil
		}

		val := payload[i : i+j]

		i += j + 1

		switch errorCode {
		case 'C': // SQLSTATE code
			sqlErr.SQLState = string(val)
		case 'M': // Error message
			sqlErr.Message = string(val)
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
