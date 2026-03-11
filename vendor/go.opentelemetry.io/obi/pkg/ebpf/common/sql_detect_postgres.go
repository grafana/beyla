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

type postgresPortalsKey struct {
	connInfo   BpfConnectionInfoT
	portalName string
}

const (
	kPostgresBind    = byte('B')
	kPostgresQuery   = byte('Q')
	kPostgresCommand = byte('C')

	// pgHeaderLen is the size of the Postgres message header:
	// 1 byte type + 4 bytes length field.
	pgHeaderLen = 5
)

func isPostgres(b *largebuf.LargeBuffer) bool {
	op, ok := isValidPostgresPayload(b)

	return ok && (op == kPostgresQuery || op == kPostgresCommand || op == kPostgresBind)
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
	if err != nil || size < 0 || size > 3000 {
		return 0, false
	}

	return op, true
}

// msgBody returns the raw bytes of the Postgres message body (after the 5-byte header),
// bounded by the message size field. Returns an error if the buffer is too short.
func msgBody(b *largebuf.LargeBuffer) ([]byte, error) {
	size, err := b.I32BEAt(1)
	if err != nil {
		return nil, errors.New("too short")
	}

	msgSize := min(1+int(size), b.Len())

	if msgSize < pgHeaderLen {
		return nil, errors.New("too short")
	}

	return b.UnsafeViewAt(pgHeaderLen, msgSize-pgHeaderLen)
}

// msgBodyReader returns a LargeBufferReader bounded to the Postgres message body.
// The reader is a zero-copy, allocation-free window into b: no new LargeBuffer is created.
func msgBodyReader(b *largebuf.LargeBuffer) (largebuf.LargeBufferReader, error) {
	size, err := b.I32BEAt(1)
	if err != nil {
		return largebuf.LargeBufferReader{}, errors.New("too short")
	}
	end := min(1+int(size), b.Len())
	if end < pgHeaderLen {
		return largebuf.LargeBufferReader{}, errors.New("too short")
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
		return "", "", nil, errors.New("too short, while parsing statement")
	}

	portalBytes, err := r.ReadCStr()
	if err != nil {
		return "", "", nil, errors.New("too short, while parsing portal")
	}

	// skip format codes: Int16 count + count*Int16 entries
	formats, err := r.ReadI16BE()
	if err != nil {
		return "", "", nil, errors.New("too short, while parsing format codes")
	}
	if formats > 0 {
		if err := r.Skip(2 * int(formats)); err != nil {
			return "", "", nil, errors.New("too short, while parsing format codes")
		}
	}

	// parse parameter values: Int16 count + repeated (Int32 length + bytes)
	params, err := r.ReadI16BE()
	if err != nil {
		return "", "", nil, errors.New("too short, while parsing params")
	}
	if params <= 0 {
		return string(stmtBytes), string(portalBytes), nil, nil
	}
	args := make([]string, 0, int(params))
	for range int(params) {
		argLen, err := r.ReadI32BE()
		if err != nil {
			return "", "", nil, errors.New("too short, while parsing params")
		}
		if argLen < 0 {
			// NULL parameter value (-1 in the protocol)
			continue
		}
		n := min(int(argLen), r.Remaining())
		arg, err := r.ReadN(n)
		if err != nil {
			return "", "", nil, errors.New("too short, while parsing params")
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

type postgresMessage struct {
	typ  string
	data []byte
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
		it.err = errors.New("remaining buffer too short for message header")
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
		it.err = errors.New("malformed Postgres message")
		return
	}

	payloadSize := size - sqlprune.PostgresHdrSize + 1
	if it.r.Remaining() < int(payloadSize) {
		it.err = fmt.Errorf("remaining buffer too short for message data: expected %d bytes, got %d", payloadSize, it.r.Remaining())
		return
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

	msg = postgresMessage{typ: msgType, data: data}
	return
}

func handlePostgres(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		hasSpan         bool
		op, table, stmt string
		span            request.Span
	)

	reqR := requestBuffer.NewReader()
	respR := responseBuffer.NewReader()

	if reqR.Remaining() < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres request too short")
		return span, errFallback
	}
	if respR.Remaining() < sqlprune.PostgresHdrSize+1 {
		slog.Debug("Postgres response too short")
		return span, errFallback
	}

	// ReadN(remaining) for response — materialized once for sqlprune.SQLParseError.
	respRaw, _ := respR.ReadN(respR.Remaining())

	var (
		msg      postgresMessage
		it       = postgresMessageIterator{r: reqR}
		sqlError = sqlprune.SQLParseError(request.DBPostgres, respRaw)
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
			op, table, stmt = detectSQL(msg.data)
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

			parseCtx.postgresPreparedStatements.Add(postgresPreparedStatementsKey{
				connInfo: event.ConnInfo,
				stmtName: stmtName,
			}, stmt)

			continue
		case "BIND":
			portal := strings.Clone(unix.ByteSliceToString(msg.data))
			portalLen := len(portal) + 1 // +1 for the null terminator
			stmtName := strings.Clone(unix.ByteSliceToString(msg.data[portalLen:]))

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
