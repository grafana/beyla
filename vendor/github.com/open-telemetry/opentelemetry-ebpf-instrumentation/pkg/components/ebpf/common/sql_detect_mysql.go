package ebpfcommon

import (
	"encoding/binary"
	"strings"
)

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
