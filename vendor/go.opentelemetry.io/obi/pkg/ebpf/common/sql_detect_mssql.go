// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"encoding/binary"
	"log/slog"
	"unicode/utf16"
	"unicode/utf8"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
	"go.opentelemetry.io/obi/pkg/internal/sqlprune"
)

type mssqlPreparedStatementsKey struct {
	connInfo BpfConnectionInfoT
	stmtID   uint32
}

const (
	kMSSQLHeaderLen = 8
	kMSSQLBatch     = 1
	kMSSQLRPC       = 3
	kMSSQLResponse  = 4

	kMSSQLProcIDPrepare  = 11
	kMSSQLProcIDExecute  = 12
	kMSSQLProcIDPrepExec = 13

	// TDS Token types
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/7091f6f6-b83d-4ed2-afeb-ba5013dfb18f
	kMSSQLTokenReturnValue = 0xAC

	// TDS TypeInfo type identifiers
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/d2ed21d6-527b-46ac-8035-94f6f68eb9a8
	kMSSQLTypeInt4 = 0x26 // fixed-length 4-byte integer
	kMSSQLTypeIntN = 0x38 // variable-length integer (length byte precedes value)

	// Fixed lengths for TDS RETURNVALUE (0xAC) token fields that follow the name
	kMSSQLStatusLen   = 1
	kMSSQLUserTypeLen = 4
	kMSSQLFlagsLen    = 2
	// Sum of Status, UserType, and Flags fields
	kMSSQLReturnValueMetadataLen = kMSSQLStatusLen + kMSSQLUserTypeLen + kMSSQLFlagsLen

	// Maximum size of a single TDS packet as defined by the protocol.
	// Defaults to 4096, but can be negotiated up to 32767.
	kMSSQLMaxPacketSize = 32767
)

// isMSSQL checks whether b looks like a TDS packet carrying SQL traffic.
// It intentionally excludes login (0x10) and pre-login (0x12) packet types:
// those are accepted by the BPF classifier to identify the connection early,
// but they carry no SQL and are never passed to this parser.
func isMSSQL(b *largebuf.LargeBuffer) bool {
	if b.Len() < kMSSQLHeaderLen {
		return false
	}

	pktType, err := b.U8At(0)
	if err != nil {
		return false
	}
	if pktType != kMSSQLBatch && pktType != kMSSQLRPC && pktType != kMSSQLResponse {
		return false
	}

	// Status byte check: upper 4 bits are reserved and should be 0.
	// This helps filter out random binary data that might match the packet type.
	status, err := b.U8At(1)
	if err != nil {
		return false
	}
	if (status & 0xF0) != 0 {
		return false
	}

	// Length is big-endian in TDS. It's the total number of bytes in the Packet
	// including the 8-byte header.
	length, err := b.U16BEAt(2)
	if err != nil {
		return false
	}

	// Check the length:
	// 1. MUST be at least 8 bytes (the size of the header itself).
	// 2. MUST be less than or equal to the maximum allowable negotiated packet
	//    size (32,767 bytes).
	// Note: While the *negotiated* packet size must be between 512 and 32,767,
	// individual packets can be much smaller (e.g., a simple SELECT batch).
	if length < uint16(kMSSQLHeaderLen) || length > kMSSQLMaxPacketSize {
		return false
	}

	// The Window byte (at offset 7) is currently unused and should be 0.
	window, err := b.U8At(7)
	if err != nil {
		return false
	}
	return window == 0
}

func ucs2ToUTF8(b []byte) []byte {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	out := make([]byte, 0, len(b))

	for i := 0; i < len(b); i += 2 {
		u1 := binary.LittleEndian.Uint16(b[i:])

		if utf16.IsSurrogate(rune(u1)) && i+2 < len(b) {
			u2 := binary.LittleEndian.Uint16(b[i+2:])
			if r := utf16.DecodeRune(rune(u1), rune(u2)); r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
				i += 2
				continue
			}
		}

		out = utf8.AppendRune(out, rune(u1))
	}

	return out
}

// extractTDSPayloads iterates over all TDS packets in b and returns their
// concatenated payload bytes with every 8-byte packet header stripped out.
// This is necessary because a single TDS message may span multiple packets,
// and naively treating the whole buffer as one payload would corrupt decoding
// wherever an embedded packet header appears.
func extractTDSPayloads(b *largebuf.LargeBuffer) []byte {
	total := b.Len()
	var payload []byte

	for offset := 0; offset+kMSSQLHeaderLen <= total; {
		pktLen, err := b.U16BEAt(offset + 2)
		if err != nil || int(pktLen) < kMSSQLHeaderLen || offset+int(pktLen) > total {
			break
		}
		payloadLen := int(pktLen) - kMSSQLHeaderLen
		if payloadLen > 0 {
			chunk, err := b.UnsafeViewAt(offset+kMSSQLHeaderLen, payloadLen)
			if err != nil {
				break
			}
			payload = append(payload, chunk...)
		}
		offset += int(pktLen)
	}

	return payload
}

func mssqlExtractBatchSQL(b *largebuf.LargeBuffer) (string, string, string) {
	if b.Len() <= kMSSQLHeaderLen {
		return "", "", ""
	}

	pktType, _ := b.U8At(0)
	if pktType == kMSSQLBatch {
		stmt := ucs2ToUTF8(extractTDSPayloads(b))
		return detectSQL(stmt)
	}

	return "", "", ""
}

func handleMSSQL(parseCtx *EBPFParseContext, event *TCPRequestInfo, requestBuffer, responseBuffer *largebuf.LargeBuffer) (request.Span, error) {
	var (
		op, table, stmt string
		span            request.Span
	)

	if requestBuffer.Len() < kMSSQLHeaderLen {
		slog.Debug("MSSQL request too short")
		return span, errFallback
	}

	reqRaw := requestBuffer.UnsafeView()
	respRaw := responseBuffer.UnsafeView()

	sqlCommand := sqlprune.SQLParseCommandID(request.DBMSSQL, reqRaw)
	sqlError := sqlprune.SQLParseError(request.DBMSSQL, respRaw)

	switch sqlCommand {
	case "SQL_BATCH":
		op, table, stmt = mssqlExtractBatchSQL(requestBuffer)
	case "RPC":
		procID, r, err := parseMSSQLRPC(requestBuffer)
		if err == nil {
			payload := r.Bytes()
			switch procID {
			case kMSSQLProcIDPrepExec:
				text := ucs2ToUTF8(payload)
				op, table, stmt = detectSQL(text)
			case kMSSQLProcIDPrepare:
				text := ucs2ToUTF8(payload)
				_, _, stmt = detectSQL(text)
				handle := parseHandleFromPrepareResponse(responseBuffer)
				if handle != 0 && stmt != "" {
					parseCtx.mssqlPreparedStatements.Add(mssqlPreparedStatementsKey{
						connInfo: event.ConnInfo,
						stmtID:   handle,
					}, stmt)
					return span, errIgnore
				}
			case kMSSQLProcIDExecute:
				handle := parseHandleFromExecute(r)
				if handle != 0 {
					var found bool
					stmt, found = parseCtx.mssqlPreparedStatements.Get(mssqlPreparedStatementsKey{
						connInfo: event.ConnInfo,
						stmtID:   handle,
					})
					if found {
						op, table = sqlprune.SQLParseOperationAndTable(stmt)
					}
				}
			}
		}
	}

	if !validSQL(op, table, request.DBMSSQL) {
		slog.Debug("MSSQL operation and/or table are invalid", "stmt", stmt)
		return span, errFallback
	}

	return TCPToSQLToSpan(event, op, table, stmt, request.DBMSSQL, sqlCommand, sqlError), nil
}

func parseMSSQLRPC(b *largebuf.LargeBuffer) (uint16, largebuf.LargeBufferReader, error) {
	if b.Len() < kMSSQLHeaderLen+2 {
		return 0, largebuf.LargeBufferReader{}, errFallback
	}

	firstPktLen, err := b.U16BEAt(2)
	if err != nil || int(firstPktLen) < kMSSQLHeaderLen || int(firstPktLen) > b.Len() {
		return 0, largebuf.LargeBufferReader{}, errFallback
	}

	// Parse ProcID from the first packet's payload. The RPC header fields
	// (NameLen, ProcID/Name, OptionFlags) are always in the first TDS packet.
	r, err := b.NewLimitedReader(kMSSQLHeaderLen, int(firstPktLen))
	if err != nil {
		return 0, largebuf.LargeBufferReader{}, err
	}

	nameLen, err := r.ReadU16LE()
	if err != nil {
		return 0, largebuf.LargeBufferReader{}, err
	}

	var procID uint16
	if nameLen == 0xFFFF {
		// ProcID follows NameLen when it is 0xFFFF
		procID, err = r.ReadU16LE()
	} else {
		// Skip the name string (UCS-2, so 2 bytes per char)
		err = r.Skip(int(nameLen) * 2)
	}

	if err != nil {
		return 0, largebuf.LargeBufferReader{}, err
	}

	if err := r.Skip(2); err != nil { // OptionFlags
		return procID, largebuf.LargeBufferReader{}, err
	}

	// headerConsumed is the number of bytes at the start of the TDS payload
	// used by the RPC header (NameLen + ProcID/Name + OptionFlags).
	headerConsumed := r.ReadOffset() - kMSSQLHeaderLen

	// Extract parameters from all TDS packets so that multi-packet RPC
	// requests are handled correctly. Strip the RPC header from the front.
	allPayloads := extractTDSPayloads(b)
	if headerConsumed > len(allPayloads) {
		return procID, largebuf.LargeBufferReader{}, errFallback
	}

	return procID, largebuf.NewLargeBufferFrom(allPayloads[headerConsumed:]).NewReader(), nil
}

func parseHandleFromExecute(r largebuf.LargeBufferReader) uint32 {
	nameLen, err := r.ReadU8()
	if err != nil {
		return 0
	}

	if err := r.Skip(int(nameLen) * 2); err != nil { // name (UCS-2)
		return 0
	}

	if err := r.Skip(1); err != nil { // status
		return 0
	}

	typ, err := r.ReadU8()
	if err != nil {
		return 0
	}

	switch typ {
	case kMSSQLTypeInt4:
		val, _ := r.ReadU32LE()
		return val
	case kMSSQLTypeIntN:
		length, err := r.ReadU8()
		if err == nil && length == 4 {
			val, _ := r.ReadU32LE()
			return val
		}
	}
	return 0
}

func parseHandleFromPrepareResponse(b *largebuf.LargeBuffer) uint32 {
	payload := extractTDSPayloads(b)
	if len(payload) == 0 {
		return 0
	}

	r := largebuf.NewLargeBufferFrom(payload).NewReader()

	for {
		idx := r.IndexByte(kMSSQLTokenReturnValue)
		if idx < 0 {
			break
		}

		_ = r.Skip(idx + 1)

		if r.Remaining() < 3 {
			continue
		}

		_ = r.Skip(2) // Ordinal
		nameLen, _ := r.ReadU8()

		metadataLen := int(nameLen)*2 + kMSSQLReturnValueMetadataLen
		if r.Remaining() < metadataLen+1 {
			continue
		}

		_ = r.Skip(metadataLen)
		typ, _ := r.ReadU8()

		switch typ {
		case kMSSQLTypeInt4:
			if r.Remaining() >= 4 {
				val, _ := r.ReadU32LE()
				return val
			}
		case kMSSQLTypeIntN:
			length, _ := r.ReadU8()
			if length == 4 && r.Remaining() >= 4 {
				val, _ := r.ReadU32LE()
				return val
			}
		}
	}
	return 0
}
