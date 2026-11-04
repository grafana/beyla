// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type postgresPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtName string
}

type postgresPreparedStatement struct {
	query            string
	searchPathChange postgresSearchPathChange
}

type postgresPortalsKey struct {
	connInfo   BpfConnectionInfoT
	portalName string
}

const (
	kPostgresBind    = byte('B')
	kPostgresQuery   = byte('Q')
	kPostgresCommand = byte('C')
	kPostgresParse   = byte('P')
	kPostgresSync    = byte('S')

	kPostgresParseComplete      = byte('1')
	kPostgresBindComplete       = byte('2')
	kPostgresCommandComplete    = byte('C')
	kPostgresDataRow            = byte('D')
	kPostgresEmptyQueryResponse = byte('I')
	kPostgresErrorResponse      = byte('E')
	kPostgresPortalSuspended    = byte('s')
	kPostgresReadyForQuery      = byte('Z')

	// pgHeaderLen is the size of the Postgres message header:
	// 1 byte type + 4 bytes length field.
	pgHeaderLen = 5

	// StartupMessage major protocol version (3.x: 3.0 since PG 7.4, 3.2 since PG 18)
	pgStartupProtocolMajor = 3
	// pgStartupMinLen: 4 bytes length + 4 bytes protocol + 1 byte terminator
	pgStartupMinLen     = 9
	pgStartupMaxLen     = 10000
	pgSSLRequestCode    = 80877103
	pgGSSENCRequestCode = 80877104
)

var (
	errPGTooShort                     = errors.New("too short")
	errPGTooShortStatement            = errors.New("too short, while parsing statement")
	errPGTooShortPortal               = errors.New("too short, while parsing portal")
	errPGTooShortFormatCodes          = errors.New("too short, while parsing format codes")
	errPGTooShortParams               = errors.New("too short, while parsing params")
	errPGRemainingTooShortHeader      = errors.New("remaining buffer too short for message header")
	errPGMalformedMessage             = errors.New("malformed Postgres message")
	errPGRemainingTooShortMessageData = errors.New("remaining buffer too short for message data")
)

func isPostgres(b *largebuf.LargeBuffer) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery || op == kPostgresCommand || op == kPostgresBind || op == kPostgresParse)
}

func isPostgresBindCommand(b *largebuf.LargeBuffer) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresBind)
}

func isPostgresQueryCommand(b *largebuf.LargeBuffer) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery)
}

func isValidPostgresPayload(b *largebuf.LargeBuffer) (byte, bool) {
	// https://github.com/postgres/postgres/blob/master/src/interfaces/libpq/fe-protocol3.c#L97
	if b.Len() < pgHeaderLen {
		return 0, false
	}

	op, err := b.U8At(0)
	if err != nil {
		return 0, false
	}

	size, err := b.I32BEAt(1)
	// The declared length includes the four-byte length field itself.
	if err != nil || size < pgHeaderLen-1 || size > 3000 {
		return 0, false
	}

	return op, true
}

type postgresBodyStatus uint8

const (
	postgresBodyInvalid postgresBodyStatus = iota
	postgresBodyIncomplete
	postgresBodyValid
)

// postgresSQLBodyStatus bounds validation to the first declared message, not
// the capture boundary or any later pipelined messages.
func postgresSQLBodyStatus(b *largebuf.LargeBuffer) postgresBodyStatus {
	if b.Len() < pgHeaderLen {
		return postgresBodyIncomplete
	}
	op, ok := isValidPostgresPayload(b)
	if !ok || (op != kPostgresQuery && op != kPostgresCommand && op != kPostgresBind && op != kPostgresParse) {
		return postgresBodyInvalid
	}
	size, _ := b.I32BEAt(1)
	if int(size)+1 > b.Len() {
		return postgresBodyIncomplete
	}
	r, err := msgBodyReader(b)
	if err != nil {
		return postgresBodyInvalid
	}
	if validPostgresSQLBody(op, &r) {
		return postgresBodyValid
	}
	return postgresBodyInvalid
}

func validPostgresSQLBody(op byte, r *largebuf.LargeBufferReader) bool {
	// Q/C carry one C string; B starts with a portal name; P starts with a statement name.
	if _, err := r.ReadCStr(); err != nil {
		return false
	}
	if op == kPostgresParse {
		return readPostgresParse(r)
	}
	if op != kPostgresBind {
		return r.Remaining() == 0
	}
	if _, err := r.ReadCStr(); err != nil {
		return false
	}
	formats, ok := readPostgresFormats(r)
	if !ok {
		return false
	}
	params, err := r.ReadU16BE()
	if err != nil || (formats > 1 && formats != params) {
		return false
	}
	for range int(params) {
		length, err := r.ReadI32BE()
		if err != nil || length < -1 {
			return false
		}
		if length >= 0 {
			if err := r.Skip(int(length)); err != nil {
				return false
			}
		}
	}
	_, ok = readPostgresFormats(r)
	return ok && r.Remaining() == 0
}

func readPostgresParse(r *largebuf.LargeBufferReader) bool {
	if _, err := r.ReadCStr(); err != nil {
		return false
	}
	params, err := r.ReadU16BE()
	if err != nil || int(params) > r.Remaining()/4 {
		return false
	}
	if err := r.Skip(int(params) * 4); err != nil {
		return false
	}
	return r.Remaining() == 0
}

func readPostgresFormats(r *largebuf.LargeBufferReader) (uint16, bool) {
	count, err := r.ReadU16BE()
	if err != nil || int(count) > r.Remaining()/2 {
		return 0, false
	}
	for range int(count) {
		format, err := r.ReadU16BE()
		if err != nil || format > 1 {
			return 0, false
		}
	}
	return count, true
}

// msgBody returns the raw bytes of the Postgres message body (after the 5-byte header),
// bounded by the message size field. Returns an error if the buffer is too short.
func msgBody(b *largebuf.LargeBuffer) ([]byte, error) {
	size, err := b.I32BEAt(1)
	if err != nil {
		return nil, errPGTooShort
	}

	msgSize := min(1+int(size), b.Len())

	if msgSize < pgHeaderLen {
		return nil, errPGTooShort
	}

	return b.UnsafeViewAt(pgHeaderLen, msgSize-pgHeaderLen)
}

// msgBodyReader returns a LargeBufferReader bounded to the Postgres message body.
// The reader is a zero-copy, allocation-free window into b: no new LargeBuffer is created.
func msgBodyReader(b *largebuf.LargeBuffer) (largebuf.LargeBufferReader, error) {
	size, err := b.I32BEAt(1)
	if err != nil {
		return largebuf.LargeBufferReader{}, errPGTooShort
	}
	end := min(1+int(size), b.Len())
	if end < pgHeaderLen {
		return largebuf.LargeBufferReader{}, errPGTooShort
	}
	return b.NewLimitedReader(pgHeaderLen, end)
}

//nolint:cyclop
func parsePostgresBindCommand(b *largebuf.LargeBuffer) (string, string, []string, error) {
	r, err := msgBodyReader(b)
	if err != nil {
		return "", "", nil, err
	}

	stmtBytes, err := r.ReadCStr()
	if err != nil {
		return "", "", nil, errPGTooShortStatement
	}

	portalBytes, err := r.ReadCStr()
	if err != nil {
		return "", "", nil, errPGTooShortPortal
	}

	if _, ok := readPostgresFormats(&r); !ok {
		return "", "", nil, errPGTooShortFormatCodes
	}

	// parse parameter values: Int16 count + repeated (Int32 length + bytes)
	params, err := r.ReadI16BE()
	if err != nil {
		return "", "", nil, errPGTooShortParams
	}
	if params <= 0 {
		return string(stmtBytes), string(portalBytes), nil, nil
	}
	args := make([]string, 0, int(params))
	for range int(params) {
		argLen, err := r.ReadI32BE()
		if err != nil {
			return "", "", nil, errPGTooShortParams
		}
		if argLen < 0 {
			// NULL parameter value (-1 in the protocol)
			continue
		}
		n := min(int(argLen), r.Remaining())
		arg, err := r.ReadN(n)
		if err != nil {
			return "", "", nil, errPGTooShortParams
		}
		args = append(args, string(arg))
	}

	return string(stmtBytes), string(portalBytes), args, nil
}

func parsePosgresQueryCommand(b *largebuf.LargeBuffer) ([]byte, error) {
	body, err := msgBody(b)
	if err != nil {
		return nil, err
	}
	// Query messages are null-terminated in the Postgres wire protocol; strip the trailing null.
	return bytes.TrimRight(body, "\x00"), nil
}

func postgresPreparedStatements(b *largebuf.LargeBuffer) (string, string, string) {
	var op, table, sql string
	if isPostgresBindCommand(b) {
		statement, portal, args, err := parsePostgresBindCommand(b)
		if err == nil {
			op = "PREPARED STATEMENT"
			table = fmt.Sprintf("%s.%s", statement, portal)
			var sqlBuilder strings.Builder
			for _, arg := range args {
				if isASCII(arg) {
					sqlBuilder.WriteString(arg)
					sqlBuilder.WriteString(" ")
				}
			}
			sql = sqlBuilder.String()
		}
	} else if isPostgresQueryCommand(b) {
		text, err := parsePosgresQueryCommand(b)
		if err == nil {
			if asciiIndexFold(text, sqlExecuteKeyword) == 0 {
				op = "EXECUTE"
				rest := text[len(sqlExecuteKeyword):]
				before, _, _ := bytes.Cut(rest, []byte{' '})
				table = string(before)
				sql = string(text)
			}
		}
	}

	return op, table, sql
}

// StartupMessage: Int32 length, Int32 protocol, then null-terminated key/value pairs
func parsePostgresStartup(b *largebuf.LargeBuffer) (postgresNamespace, bool) {
	r := b.NewReader()
	// BPF drops 1-byte reads, so a refused SSL/GSSENC negotiation ('N') glues its request to the startup
	for range 3 {
		msgLen, err := r.ReadI32BE()
		if err != nil || msgLen < 8 || msgLen > pgStartupMaxLen {
			return postgresNamespace{}, false
		}
		code, err := r.ReadI32BE()
		if err != nil {
			return postgresNamespace{}, false
		}
		if (code == pgSSLRequestCode || code == pgGSSENCRequestCode) && msgLen == 8 {
			continue
		}
		// trailing bytes past the startup's own length = some other length-prefixed protocol
		if code>>16 != pgStartupProtocolMajor || msgLen < pgStartupMinLen ||
			int(msgLen)-8 < r.Remaining() {
			return postgresNamespace{}, false
		}
		return parsePostgresStartupParams(&r, r.Remaining() == int(msgLen)-8)
	}
	return postgresNamespace{}, false
}

func parsePostgresStartupParams(r *largebuf.LargeBufferReader, complete bool) (postgresNamespace, bool) {
	var db, user, searchPath, optionsSearchPath string
	hasSearchPath, hasOptionsSearchPath := false, false
	for {
		key, err := r.ReadCStr()
		if err != nil || len(key) == 0 {
			break
		}
		// ReadCStr may return the reader's scratch buffer, which the next read reuses
		k := string(key)
		val, err := r.ReadCStr()
		if err != nil {
			break
		}
		switch k {
		case "database":
			db = string(val)
		case "user":
			user = string(val)
		case pgSearchPathParam:
			searchPath, hasSearchPath = string(val), true
		case pgOptionsParam:
			optionsSearchPath, hasOptionsSearchPath = searchPathFromStartupOptions(string(val))
		}
	}
	if db == "" && complete {
		// the database name defaults to the user name, but a truncated capture may hide an explicit database param
		db = user
	}
	if !hasSearchPath && hasOptionsSearchPath {
		searchPath = optionsSearchPath
	}
	schema := firstSearchPathSchema(searchPath)
	return postgresNamespace{db: db, startupSchema: schema, schema: schema}, db != ""
}

type postgresMessage struct {
	typ     string
	data    []byte
	partial bool
	sync    bool
}

func parsePostgresBindNames(data []byte) (portalName, statementName string, ok bool) {
	portalEnd := bytes.IndexByte(data, 0)
	if portalEnd < 0 {
		return "", "", false
	}

	stmtStart := portalEnd + 1
	if stmtStart >= len(data) {
		return "", "", false
	}

	return string(data[:portalEnd]), unix.ByteSliceToString(data[stmtStart:]), true
}

type postgresMessageIterator struct {
	r   largebuf.LargeBufferReader
	err error
	eof bool
}

func (it *postgresMessageIterator) isEOF() bool {
	return it.eof
}

func (it *postgresMessageIterator) next() (msg postgresMessage) {
	if it.err != nil || it.r.Remaining() == 0 {
		it.eof = true
		return
	}
	if it.r.Remaining() < sqlprune.PostgresHdrSize {
		it.err = errPGRemainingTooShortHeader
		return
	}

	// Read the 5-byte header (type byte + 4-byte size) atomically.
	// SQLParseCommandID needs buf[0] as the type byte; it requires len(buf) >= PostgresHdrSize (5).
	hdrBuf, err := it.r.ReadN(sqlprune.PostgresHdrSize)
	if err != nil {
		it.err = err
		return
	}
	msgType := sqlprune.SQLParseCommandID(request.DBPostgres, hdrBuf)
	size := int32(binary.BigEndian.Uint32(hdrBuf[1:5]))

	if size < sqlprune.PostgresHdrSize-1 {
		it.err = errPGMalformedMessage
		return
	}

	payloadSize := size - sqlprune.PostgresHdrSize + 1
	partial := false
	if it.r.Remaining() < int(payloadSize) {
		if msgType != "PARSE" {
			it.err = errPGRemainingTooShortMessageData
			return
		}

		payloadSize = int32(it.r.Remaining())
		partial = true
	}

	// ReadN is safe: all uses of msg.data convert it to a Go string before the next
	// it.next() call, so scratch overwrite between iterations is not a concern.
	// Use empty non-nil slice for zero-length payloads to match []byte{} semantics.
	data := []byte{}
	if payloadSize > 0 {
		data, err = it.r.ReadN(int(payloadSize))
		if err != nil {
			it.err = err
			return
		}
	}

	msg = postgresMessage{typ: msgType, data: data, partial: partial, sync: hdrBuf[0] == kPostgresSync}
	return
}

type postgresResponse struct {
	executed bool
	sqlError *request.SQLError

	parsesCompleted []int
}

func (r postgresResponse) parseCompleted(syncIndex, parseIndex int) bool {
	return syncIndex < len(r.parsesCompleted) && parseIndex < r.parsesCompleted[syncIndex]
}

func parsePostgresResponse(response []byte) postgresResponse {
	result := postgresResponse{parsesCompleted: []int{0}}
	bound := false

	for len(response) >= sqlprune.PostgresHdrSize {
		size := int(binary.BigEndian.Uint32(response[1:sqlprune.PostgresHdrSize]))
		messageSize := size + 1
		if size < sqlprune.PostgresHdrSize-1 || messageSize > len(response) {
			break
		}

		message := response[:messageSize]
		switch message[0] {
		case kPostgresParseComplete:
			result.parsesCompleted[len(result.parsesCompleted)-1]++
		case kPostgresReadyForQuery:
			result.parsesCompleted = append(result.parsesCompleted, 0)
		case kPostgresBindComplete:
			bound = true
		case kPostgresCommandComplete, kPostgresDataRow, kPostgresEmptyQueryResponse, kPostgresPortalSuspended:
			result.executed = true
		case kPostgresErrorResponse:
			result.sqlError = sqlprune.SQLParseError(request.DBPostgres, message)
			result.executed = result.executed || bound
		}

		response = response[messageSize:]
	}

	return result
}

func handlePostgres(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		hasSpan          bool
		op, stmt         string
		tables           []string
		span             request.Span
		searchPathChange postgresSearchPathChange
	)

	reqR := requestBuffer.NewReader()
	respR := responseBuffer.NewReader()

	if reqR.Remaining() < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres request too short")
		return span, errFallback
	}
	if respR.Remaining() < sqlprune.PostgresHdrSize {
		slog.Debug("Postgres response too short")
		return span, errFallback
	}

	// ReadN(remaining) for response — materialized once for sqlprune.SQLParseError.
	respRaw, _ := respR.ReadN(respR.Remaining())

	response := parsePostgresResponse(respRaw)
	var (
		msg      postgresMessage
		it       = postgresMessageIterator{r: reqR}
		sqlError = response.sqlError

		syncIndex, parseIndex int
		rejectedParses        map[string]postgresPreparedStatement
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

		if msg.sync {
			syncIndex++
			parseIndex = 0
			continue
		}

		switch msg.typ {
		case "QUERY":
			searchPathChange = parsePostgresSearchPathChange(msg.data)
			op, tables, stmt = detectSQL(msg.data)
			hasSpan = true
			break Loop
		case "PARSE":
			// On the PARSE command, the statement name is the first 4 bytes after the header and command ID
			// in the request buffer.
			// strings.Clone is intentional: msg.data may alias a reusable scratch buffer
			// inside LargeBufferReader; we must not keep a zero-copy reference past this iteration.
			stmtName := strings.Clone(unix.ByteSliceToString(msg.data))
			stmtNameLen := len(stmtName)
			_, _, stmt = detectSQL(msg.data[stmtNameLen:])

			prepared := postgresPreparedStatement{query: stmt}
			if !msg.partial && stmtNameLen < len(msg.data) {
				prepared.searchPathChange = parsePostgresSearchPathChange(msg.data[stmtNameLen+1:])
			}

			if response.parseCompleted(syncIndex, parseIndex) {
				parseCtx.postgresPreparedStatements.Add(postgresPreparedStatementsKey{
					connInfo: event.ConnInfo,
					stmtName: stmtName,
				}, prepared)
			} else {
				if rejectedParses == nil {
					rejectedParses = map[string]postgresPreparedStatement{}
				}
				rejectedParses[stmtName] = postgresPreparedStatement{query: stmt}
			}
			parseIndex++

			if !msg.partial || !response.executed {
				continue
			}

			op, tables = sqlprune.SQLParseOperationAndTables(stmt)
			hasSpan = true
			msg.typ = "EXECUTE"
			break Loop
		case "BIND":
			portal, stmtName, ok := parsePostgresBindNames(msg.data)
			if !ok {
				continue
			}

			parseCtx.postgresPortals.Add(postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: portal,
			}, stmtName)

			continue
		case "EXECUTE":
			portalKey := postgresPortalsKey{
				connInfo:   event.ConnInfo,
				portalName: strings.Clone(unix.ByteSliceToString(msg.data)),
			}

			stmtName, found := parseCtx.postgresPortals.Get(portalKey)
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown portal", "portal", portalKey.portalName)
				continue
			}

			prepared, found := rejectedParses[stmtName]
			if !found {
				prepared, found = parseCtx.postgresPreparedStatements.Get(postgresPreparedStatementsKey{
					connInfo: event.ConnInfo,
					stmtName: stmtName,
				})
			}
			if !found {
				slog.Debug("Postgres EXECUTE command with unknown statement", "stmtName", stmtName)
				continue
			}

			stmt = prepared.query
			searchPathChange = prepared.searchPathChange

			op, tables = sqlprune.SQLParseOperationAndTables(stmt)
			hasSpan = true
			break Loop
		default:
			continue
		}
	}

	if sqlError == nil && response.executed {
		applyPostgresSearchPathChange(parseCtx, event.ConnInfo, searchPathChange)
	}

	if !hasSpan {
		return span, errIgnore
	}

	if !validSQL(op, len(tables) > 0, request.DBPostgres) {
		// This can happen for stuff like 'BEGIN', etc.
		slog.Debug("Postgres operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	span = TCPToSQLToSpan(event, op, tables, stmt, request.DBPostgres, msg.typ, sqlError)
	span.DBNamespace = postgresNamespaceForConn(parseCtx, event.ConnInfo)
	return span, nil
}
