// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

const (
	mysqlCapConnectWithDB              = uint32(0x00000008)
	mysqlCapProtocol41                 = uint32(0x00000200)
	mysqlCapSSL                        = uint32(0x00000800)
	mysqlCapSecureConnection           = uint32(0x00008000)
	mysqlCapPluginAuthLenencClientData = uint32(0x00200000)
)

const (
	mysqlHandshakeResponseSeqID    = 1
	mysqlTLSHandshakeResponseSeqID = 2
	mysqlCapabilitiesLen           = 4
	mysqlHandshakeReservedOffset   = 9
	mysqlHandshakeReservedLen      = 19
	mysqlHandshakeExtCapsOffset    = mysqlHandshakeReservedOffset + mysqlHandshakeReservedLen
	mysqlHandshakeExtCapsLen       = 4
	mysqlHandshakeResponseFixedLen = mysqlHandshakeExtCapsOffset + mysqlHandshakeExtCapsLen
)

const (
	mysqlCommandSeqID         = 0
	mysqlCommandResponseSeqID = 1
	mysqlOKPacketHeader       = uint8(0x00)
	mysqlOKPacketMinLen       = 7
)

const (
	mysqlLenEncNull = 0xfb
	mysqlLenEncInt2 = 0xfc
	mysqlLenEncInt3 = 0xfd
	mysqlLenEncInt8 = 0xfe
)

type mysqlConnInfo struct {
	db string
}

type mysqlDatabaseChange struct {
	db string
	// standalone is set when the exchange only changes the database and
	// carries no statement to report.
	standalone bool
}

type mysqlResponseStatus uint8

const (
	mysqlResponseFailed mysqlResponseStatus = iota
	mysqlResponseOK
	// Only the packet header was captured, as with libmysqlclient over TLS,
	// so OK and ERR cannot be told apart.
	mysqlResponseUnknown
)

const (
	mysqlPayloadLengthMask = 0x00ffffff
	mysqlSequenceIDShift   = 24
	mysqlWhitespace        = " \t\n\r\v\f"
)

var mysqlUseKeyword = []byte("use")

// mysqlByteAt reads one byte, checking the range first: LargeBuffer accessors
// allocate an error when reading out of range.
func mysqlByteAt(buf *largebuf.LargeBuffer, off int) (byte, bool) {
	if off < 0 || off >= buf.Len() {
		return 0, false
	}
	c, err := buf.U8At(off)
	return c, err == nil
}

func mysqlPacketHeader(buf *largebuf.LargeBuffer, off int) (int, uint8, bool) {
	if off < 0 || off+sqlprune.MySQLHdrSize > buf.Len() {
		return 0, 0, false
	}
	hdr, err := buf.U32LEAt(off)
	if err != nil {
		return 0, 0, false
	}
	return int(hdr & mysqlPayloadLengthMask), uint8(hdr >> mysqlSequenceIDShift), true
}

func parseMySQLHandshakeResponse(buf *largebuf.LargeBuffer) (mysqlConnInfo, bool) {
	off := mysqlSSLRequestEnd(buf)

	payloadLen, seqID, ok := mysqlPacketHeader(buf, off)
	if !ok || (seqID != mysqlHandshakeResponseSeqID && seqID != mysqlTLSHandshakeResponseSeqID) {
		return mysqlConnInfo{}, false
	}

	payloadOff := off + sqlprune.MySQLHdrSize
	captured := buf.Len() - payloadOff
	if payloadLen < mysqlHandshakeResponseFixedLen || captured < mysqlHandshakeResponseFixedLen || captured > payloadLen {
		return mysqlConnInfo{}, false
	}

	r, err := buf.NewLimitedReader(payloadOff, buf.Len())
	if err != nil {
		return mysqlConnInfo{}, false
	}

	caps, err := r.ReadU32LE()
	if err != nil || caps&mysqlCapProtocol41 == 0 {
		return mysqlConnInfo{}, false
	}

	if r.Skip(mysqlHandshakeReservedOffset-mysqlCapabilitiesLen) != nil || !skipMySQLZeros(&r, mysqlHandshakeReservedLen) {
		return mysqlConnInfo{}, false
	}

	if r.Skip(mysqlHandshakeExtCapsLen) != nil {
		return mysqlConnInfo{}, false
	}

	var info mysqlConnInfo
	if caps&mysqlCapConnectWithDB != 0 {
		info.db = mysqlHandshakeDatabase(&r, caps)
	}

	return info, true
}

// skipMySQLZeros consumes n bytes one at a time, so that nothing is copied,
// and reports whether they were all zero.
func skipMySQLZeros(r *largebuf.LargeBufferReader, n int) bool {
	for range n {
		if b, err := r.ReadU8(); err != nil || b != 0 {
			return false
		}
	}
	return true
}

// mysqlSSLRequestEnd returns where the HandshakeResponse starts when an
// SSLRequest is captured in the same event, and 0 otherwise.
func mysqlSSLRequestEnd(buf *largebuf.LargeBuffer) int {
	const sslRequestEnd = sqlprune.MySQLHdrSize + mysqlHandshakeResponseFixedLen

	if buf.Len() <= sslRequestEnd {
		return 0
	}

	length, seqID, ok := mysqlPacketHeader(buf, 0)
	if !ok || seqID != mysqlHandshakeResponseSeqID || length != mysqlHandshakeResponseFixedLen {
		return 0
	}

	caps, err := buf.U32LEAt(sqlprune.MySQLHdrSize)
	if err != nil || caps&mysqlCapSSL == 0 {
		return 0
	}

	if _, nextSeqID, ok := mysqlPacketHeader(buf, sslRequestEnd); !ok || nextSeqID != mysqlTLSHandshakeResponseSeqID {
		return 0
	}
	return sslRequestEnd
}

func mysqlHandshakeDatabase(r *largebuf.LargeBufferReader, caps uint32) string {
	if _, err := r.ReadCStr(); err != nil {
		return ""
	}

	if !skipMySQLAuthResponse(r, caps) {
		return ""
	}

	db, err := r.ReadCStr()
	if err != nil {
		return ""
	}
	return string(db)
}

func skipMySQLAuthResponse(r *largebuf.LargeBufferReader, caps uint32) bool {
	switch {
	case caps&mysqlCapPluginAuthLenencClientData != 0:
		authLen, ok := readMySQLLenEncInt(r)
		return ok && authLen <= uint64(r.Remaining()) && r.Skip(int(authLen)) == nil
	case caps&mysqlCapSecureConnection != 0:
		authLen, err := r.ReadU8()
		return err == nil && r.Skip(int(authLen)) == nil
	default:
		_, err := r.ReadCStr()
		return err == nil
	}
}

func readMySQLLenEncInt(r *largebuf.LargeBufferReader) (uint64, bool) {
	first, err := r.ReadU8()
	if err != nil {
		return 0, false
	}

	var size int
	switch {
	case first < mysqlLenEncNull:
		return uint64(first), true
	case first == mysqlLenEncInt2:
		size = 2
	case first == mysqlLenEncInt3:
		size = 3
	case first == mysqlLenEncInt8:
		size = 8
	default:
		return 0, false
	}

	b, err := r.ReadN(size)
	if err != nil {
		return 0, false
	}

	var value uint64
	for i := size - 1; i >= 0; i-- {
		value = value<<8 | uint64(b[i])
	}
	return value, true
}

// parseMySQLDatabaseChange parses the command at off, after any coalesced
// commands without a server response.
func parseMySQLDatabaseChange(req *largebuf.LargeBuffer, off int, resp *largebuf.LargeBuffer) (mysqlDatabaseChange, bool) {
	length, seqID, ok := mysqlPacketHeader(req, off)
	if !ok || seqID != mysqlCommandSeqID || length == 0 || off+sqlprune.MySQLHdrSize+length != req.Len() {
		return mysqlDatabaseChange{}, false
	}

	command, err := req.U8At(off + sqlprune.MySQLHdrSize)
	if err != nil {
		return mysqlDatabaseChange{}, false
	}

	if command == kMySQLChangeUser {
		return mysqlDatabaseChange{standalone: true}, true
	}

	if command != kMySQLInitDB && command != kMySQLQuery {
		return mysqlDatabaseChange{}, false
	}

	status := mysqlCommandResponseStatus(resp)
	if status == mysqlResponseFailed {
		return mysqlDatabaseChange{}, false
	}

	argOff := off + sqlprune.MySQLHdrSize + 1
	if command == kMySQLQuery {
		argOff = skipMySQLQueryAttributes(req, argOff)
	}
	if argOff == req.Len() {
		return mysqlDatabaseChange{}, false
	}

	if command == kMySQLQuery && !isMySQLUse(req, argOff) {
		return mysqlDatabaseChange{}, false
	}

	if command == kMySQLQuery && hasMySQLStatementAfter(req, argOff) {
		return mysqlDatabaseChange{}, true
	}

	argReader, err := req.NewLimitedReader(argOff, req.Len())
	if err != nil {
		return mysqlDatabaseChange{}, false
	}
	arg, err := argReader.ReadN(argReader.Remaining())
	if err != nil {
		return mysqlDatabaseChange{}, false
	}

	if command == kMySQLInitDB {
		return mysqlDatabaseChange{db: knownMySQLDatabase(string(arg), status), standalone: true}, true
	}

	db, isUse := sqlprune.SQLParseUseDatabase(string(arg))
	return mysqlDatabaseChange{db: knownMySQLDatabase(db, status), standalone: db != ""}, isUse
}

// skipMySQLQueryAttributes skips the empty query attributes that clients
// prefix to COM_QUERY text when CLIENT_QUERY_ATTRIBUTES is negotiated
// (parameter_count 0, parameter_set_count 1). Queries that carry attributes
// are left as is and are not recognized as USE.
func skipMySQLQueryAttributes(buf *largebuf.LargeBuffer, off int) int {
	paramCount, ok := mysqlByteAt(buf, off)
	if !ok || paramCount != 0 {
		return off
	}
	if paramSetCount, ok := mysqlByteAt(buf, off+1); ok && paramSetCount == 1 {
		return off + 2
	}
	return off
}

// isMySQLUse reports whether the query at off starts with USE, skipping
// whitespace and comments in place so that other queries are never copied.
func isMySQLUse(buf *largebuf.LargeBuffer, off int) bool {
	off = skipMySQLSpaceAndComments(buf, off)
	for i, want := range mysqlUseKeyword {
		c, ok := mysqlByteAt(buf, off+i)
		if !ok || toLowerASCII(c) != want {
			return false
		}
	}

	next, ok := mysqlByteAt(buf, off+len(mysqlUseKeyword))
	if !ok {
		return off+len(mysqlUseKeyword) == buf.Len()
	}
	return isMySQLWhitespace(next) || next == '`' || next == '/' || next == '#' || next == '-'
}

// hasMySQLStatementAfter reports whether anything but whitespace and comments
// follows the first ';' of the query, without copying it.
func hasMySQLStatementAfter(buf *largebuf.LargeBuffer, off int) bool {
	semicolon := buf.IndexByteAt(off, ';')
	return semicolon >= 0 && skipMySQLSpaceAndComments(buf, semicolon+1) < buf.Len()
}

func skipMySQLSpaceAndComments(buf *largebuf.LargeBuffer, off int) int {
	for off < buf.Len() {
		c, _ := mysqlByteAt(buf, off)
		next, _ := mysqlByteAt(buf, off+1)
		switch {
		case isMySQLWhitespace(c):
			off++
		case c == '#', c == '-' && next == '-':
			off = mysqlLineEnd(buf, off)
		case c == '/' && next == '*':
			off = mysqlBlockCommentEnd(buf, off+2)
		default:
			return off
		}
	}
	return off
}

func mysqlLineEnd(buf *largebuf.LargeBuffer, off int) int {
	if lf := buf.IndexByteAt(off, '\n'); lf >= 0 {
		return lf + 1
	}
	return buf.Len()
}

func mysqlBlockCommentEnd(buf *largebuf.LargeBuffer, off int) int {
	for {
		star := buf.IndexByteAt(off, '*')
		if star < 0 {
			return buf.Len()
		}
		if c, ok := mysqlByteAt(buf, star+1); ok && c == '/' {
			return star + 2
		}
		off = star + 1
	}
}

func isMySQLWhitespace(c byte) bool {
	return strings.IndexByte(mysqlWhitespace, c) >= 0
}

func mysqlCommandResponseStatus(resp *largebuf.LargeBuffer) mysqlResponseStatus {
	length, seqID, ok := mysqlPacketHeader(resp, 0)
	if !ok || seqID != mysqlCommandResponseSeqID {
		return mysqlResponseFailed
	}
	if resp.Len() == sqlprune.MySQLHdrSize {
		return mysqlResponseUnknown
	}

	header, err := resp.U8At(sqlprune.MySQLHdrSize)
	if err == nil && header == mysqlOKPacketHeader && length >= mysqlOKPacketMinLen {
		return mysqlResponseOK
	}
	return mysqlResponseFailed
}

func knownMySQLDatabase(db string, status mysqlResponseStatus) string {
	if status == mysqlResponseOK {
		return db
	}
	return ""
}

// trackMySQLConnState records the handshake or a database change and reports
// whether the exchange has nothing else to report.
func trackMySQLConnState(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, req *largebuf.LargeBuffer, reqOff int, resp *largebuf.LargeBuffer) bool {
	if info, ok := parseMySQLHandshakeResponse(req); ok {
		parseCtx.mysqlConns.Add(connInfo, info)
		return true
	}

	change, ok := parseMySQLDatabaseChange(req, reqOff, resp)
	if !ok {
		return false
	}

	info, found := parseCtx.mysqlConns.Get(connInfo)
	if !found && change.db == "" {
		return false
	}

	info.db = change.db
	parseCtx.mysqlConns.Add(connInfo, info)
	return change.standalone
}

func setMySQLConnAttributes(parseCtx *EBPFParseContext, connInfo BpfConnectionInfoT, span *request.Span) {
	if parseCtx.mysqlConns == nil {
		return
	}

	info, ok := parseCtx.mysqlConns.Get(connInfo)
	if !ok {
		return
	}

	span.DBNamespace = info.db
}
