// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	MySQLHdrSize                  = 4
	MySQLErrMinLen                = 8
	MySQLErrPacketMarker   byte   = 0xff
	MySQLStateMarker       byte   = '#'
	MySQLProgressReporting uint16 = 0xffff
)

func parseMySQLCommandID(buf []uint8) uint8 {
	if len(buf) < MySQLHdrSize+1 {
		return 0
	}
	// The first byte after the header is the command ID
	return buf[MySQLHdrSize]
}

// MySQL error packet format - https://dev.mysql.com/doc/dev/mysql-server/8.4.3/page_protocol_basic_err_packet.html
//
// +---------+--------+------------+--------------------+
// | Field   | Size   | Description                   |
// +---------+--------+-------------------------------+
// | header  | 1 byte | always 0xFF for errors        |
// | code    | 2 byte | error code (little endian)    |
// | sqlstate_marker | 1 byte | '#' (only if CLIENT_PROTOCOL_41) |
// | sqlstate | 5 byte | SQL state (like "HY000")     |
// | message | N      | human-readable error message  |
// +---------+--------+-------------------------------+
func parseMySQLError(buf []uint8) *request.SQLError {
	var (
		sqlErr request.SQLError
		offset = MySQLHdrSize
		length = len(buf)
	)

	if length < MySQLErrMinLen {
		return nil // Not an error packet
	}

	if buf[offset] != MySQLErrPacketMarker {
		return nil // Not an error packet
	}
	offset++

	sqlErr.Code = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2

	// https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
	if sqlErr.Code < 1002 || sqlErr.Code > 4167 {
		return nil // Invalid error code
	}

	if sqlErr.Code != MySQLProgressReporting {
		if buf[offset] == MySQLStateMarker {
			if len(buf) < (MySQLErrMinLen + 6) {
				return nil
			}
			// Skip the SQL state marker
			offset++
			// Read the SQL state
			sqlErr.SQLState = string(MySQLStateMarker) + string(buf[offset:offset+5])
			offset += 5
		}
		// Read the error message
		sqlErr.Message = unix.ByteSliceToString(buf[offset:])
	}

	return &sqlErr
}

func mysqlCommandIDToString(commandID uint8) string {
	switch commandID {
	case 0x3:
		return "QUERY"
	case 0x16:
		return "STMT_PREPARE"
	case 0x17:
		return "STMT_EXECUTE"
	default:
		return ""
	}
}

func mysqlParseStatementID(buf []byte) uint32 {
	if len(buf) < MySQLHdrSize+1+4 {
		return 0
	}
	// The statement ID is a 4-byte little-endian integer after the header and command ID
	return binary.LittleEndian.Uint32(buf[MySQLHdrSize+1:])
}
