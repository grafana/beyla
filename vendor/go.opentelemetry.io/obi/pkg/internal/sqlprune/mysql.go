// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sqlprune // import "go.opentelemetry.io/obi/pkg/internal/sqlprune"

import (
	"encoding/binary"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	MySQLHdrSize                  = 4
	MySQLErrMinLen                = 7
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

	// The capture may hold trailing packets or cut the message short
	packetEnd := MySQLHdrSize + int(binary.LittleEndian.Uint32(buf)&0x00ffffff)
	if packetEnd < MySQLErrMinLen {
		return nil // Not an error packet
	}
	length = min(length, packetEnd)

	if buf[offset] != MySQLErrPacketMarker {
		return nil // Not an error packet
	}
	offset++

	sqlErr.Code = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2

	if sqlErr.Code == 0 {
		return nil
	}

	// MariaDB progress reports share the ERR marker but are not errors.
	// Other codes may be user-defined or supplied by MySQL-compatible servers.
	if sqlErr.Code == MySQLProgressReporting {
		return nil
	}

	// A SQL state is only present when the declared packet has room for it
	if offset < length && buf[offset] == MySQLStateMarker && packetEnd >= offset+1+5 {
		if length < offset+1+5 {
			return nil
		}
		// Skip the SQL state marker
		offset++
		// Read the SQL state
		sqlErr.SQLState = string(MySQLStateMarker) + string(buf[offset:offset+5])
		offset += 5
	}
	// Read the error message
	sqlErr.Message = unix.ByteSliceToString(buf[offset:length])

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
