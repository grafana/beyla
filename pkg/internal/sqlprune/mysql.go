package sqlprune

import (
	"encoding/binary"
)

const (
	DBTypeMySQL DBType = "mysql"

	MYSQL_HDR_SIZE                  = 4
	MYSQL_ERR_MIN_LEN               = 7
	MYSQL_ERR_PACKET_MARKER  byte   = 0xff
	MYSQL_STATE_MARKER       byte   = '#'
	MYSQL_PROGRESS_REPORTING uint16 = 0xffff
)

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
func parseMySQLError(buf []uint8, length uint32) *SQLError {
	var (
		sqlErr SQLError
		offset int = MYSQL_HDR_SIZE
	)

	if length < MYSQL_ERR_MIN_LEN {
		return nil // Not an error packet
	}

	if buf[offset] != MYSQL_ERR_PACKET_MARKER {
		return nil // Not an error packet
	}
	offset += 1

	sqlErr.Code = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2

	if sqlErr.Code != MYSQL_PROGRESS_REPORTING {
		if buf[offset] == MYSQL_STATE_MARKER {
			offset += 1 // Skip the SQL state marker
			// Read the SQL state
			sqlErr.SQLState = string(MYSQL_STATE_MARKER) + string(buf[offset:offset+5])
			offset += 5
		}
		// Read the error message
		sqlErr.Message = trimNulls(string(buf[offset:]))
	}

	sqlErr.DB = DBTypeMySQL

	return &sqlErr
}

// https://dev.mysql.com/doc/mysql-errors/8.0/en/server-error-reference.html
func validateMySQLError(sqlErr *SQLError) bool {
	return sqlErr.Code >= 1002 && sqlErr.Code <= 4167 && sqlErr.Message != ""
}
