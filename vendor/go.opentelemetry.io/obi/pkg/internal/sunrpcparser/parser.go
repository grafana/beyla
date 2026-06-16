// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package sunrpcparser // import "go.opentelemetry.io/obi/pkg/internal/sunrpcparser"

import (
	"encoding/binary"
	"errors"
	"strconv"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	rpcVersion = 2

	msgCall  = 0
	msgReply = 1

	replyAccepted = 0
	replyDenied   = 1

	rejectRPCMismatch = 0
	rejectAuthError   = 1
	maxAuthStat       = 13

	acceptSuccess = 0

	// auth_flavor_t values from RFC 5531 / IANA RPC Authentication Numbers.
	authNull      = 0
	authUnix      = 1
	authShort     = 2
	authDES       = 3
	authKerb      = 4 // AUTH_KERB (Kerberos v4, deprecated)
	authRSA       = 5 // AUTH_RSA
	authRPCSECgss = 6 // RPCSEC_GSS (RFC 2203)

	rmLastFrag = 0x80000000
	rmFragLen  = 0x7fffffff

	maxRecordSize   = 1 << 20
	maxMessagesRead = 32
)

var (
	ErrNotSunRPC       = errors.New("not SunRPC")
	ErrTruncatedRecord = errors.New("truncated SunRPC record")
	ErrInvalidRPC      = errors.New("invalid SunRPC message")
)

// CallInfo holds fields parsed from an ONC RPC CALL header.
// Procedure arguments are not decoded; only CALL/REPLY header fields are extracted.
type CallInfo struct {
	Xid        uint32
	Program    uint32
	Version    uint32
	Procedure  uint32
	AuthFlavor uint32
}

// ReplyInfo holds minimal REPLY status from an ONC RPC REPLY.
type ReplyInfo struct {
	Xid          uint32
	AcceptStat   uint32
	MatchCallXid bool
	Denied       bool
}

// Result is returned by Parse.
type Result struct {
	LooksLikeSunRPC bool
	Call            *CallInfo
	Reply           *ReplyInfo
}

// IsLikelySunRPC performs a cheap check on the first TCP record.
func IsLikelySunRPC(r *largebuf.LargeBufferReader) bool {
	res, err := parseMessages(r, true)
	if err != nil {
		return false
	}
	return res.LooksLikeSunRPC
}

// Parse scans SunRPC over TCP record marking and returns the first CALL and optional REPLY.
func Parse(r *largebuf.LargeBufferReader) (Result, error) {
	return parseMessages(r, false)
}

func parseMessages(r *largebuf.LargeBufferReader, firstRecordOnly bool) (Result, error) {
	if r.Remaining() < 4 {
		return Result{}, ErrNotSunRPC
	}

	var out Result
	messages := 0

	for r.Remaining() >= 4 && messages < maxMessagesRead {
		record, err := readRecord(r)
		if err != nil {
			if out.LooksLikeSunRPC {
				return out, nil
			}
			if !firstRecordOnly && errors.Is(err, ErrTruncatedRecord) {
				return Result{}, ErrNotSunRPC
			}
			return Result{}, err
		}
		messages++
		if len(record) == 0 {
			continue
		}

		call, reply, looks, err := parseRPCRecord(record)
		if err != nil {
			if out.LooksLikeSunRPC {
				return out, nil
			}
			return Result{}, err
		}
		if !looks {
			if out.LooksLikeSunRPC {
				return out, nil
			}
			return Result{}, ErrNotSunRPC
		}

		out.LooksLikeSunRPC = true
		if call != nil && out.Call == nil {
			out.Call = call
		}
		if reply != nil && (out.Reply == nil || (out.Call != nil && reply.Xid == out.Call.Xid)) {
			reply.MatchCallXid = out.Call != nil && reply.Xid == out.Call.Xid
			out.Reply = reply
		}

		if firstRecordOnly {
			break
		}
		if out.Call != nil && out.Reply != nil && out.Reply.MatchCallXid {
			break
		}
	}

	if !out.LooksLikeSunRPC {
		return Result{}, ErrNotSunRPC
	}

	return out, nil
}

func readRecord(r *largebuf.LargeBufferReader) ([]byte, error) {
	var parts [][]byte
	total := 0

	for {
		hdr, err := r.ReadU32BE()
		if err != nil {
			if len(parts) == 0 {
				return nil, err
			}
			return nil, ErrTruncatedRecord
		}

		last := hdr&rmLastFrag != 0
		length := int(hdr & rmFragLen)
		if length < 0 || length > maxRecordSize || total+length > maxRecordSize {
			return nil, ErrNotSunRPC
		}

		fragment, err := r.ReadN(length)
		if err != nil {
			return nil, ErrTruncatedRecord
		}

		parts = append(parts, fragment)
		total += length

		if last {
			break
		}
	}

	if len(parts) == 1 {
		return parts[0], nil
	}

	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out, nil
}

func parseRPCRecord(record []byte) (*CallInfo, *ReplyInfo, bool, error) {
	if len(record) < 8 {
		return nil, nil, false, nil
	}

	xid := binary.BigEndian.Uint32(record[0:4])
	msgType := binary.BigEndian.Uint32(record[4:8])

	switch msgType {
	case msgCall:
		call, ok, err := parseCall(record[8:])
		if err != nil {
			return nil, nil, false, err
		}
		if !ok {
			return nil, nil, false, nil
		}
		call.Xid = xid
		return call, nil, true, nil
	case msgReply:
		reply, ok, err := parseReply(record[8:])
		if err != nil {
			return nil, nil, false, err
		}
		if !ok {
			return nil, nil, false, nil
		}
		reply.Xid = xid
		return nil, reply, true, nil
	default:
		return nil, nil, false, nil
	}
}

func parseCall(body []byte) (*CallInfo, bool, error) {
	if len(body) < 24 {
		return nil, false, nil
	}

	rpcvers := binary.BigEndian.Uint32(body[0:4])
	if rpcvers != rpcVersion {
		return nil, false, nil
	}

	prog := binary.BigEndian.Uint32(body[4:8])
	vers := binary.BigEndian.Uint32(body[8:12])
	proc := binary.BigEndian.Uint32(body[12:16])

	if !validProgram(prog) || vers == 0 || proc > 0xffff {
		return nil, false, nil
	}

	// CALL cred then verf: off walks the body; each readOpaqueAuth uses body[off:]
	// and off += n so the second read is verf, not a repeat of cred.
	off := 16
	flavor, n, err := readOpaqueAuth(body[off:])
	if err != nil {
		return nil, false, err
	}
	if !validAuthFlavor(flavor) {
		return nil, false, nil
	}
	off += n

	verfFlavor, n, err := readOpaqueAuth(body[off:])
	if err != nil {
		return nil, false, err
	}
	if !validAuthFlavor(verfFlavor) {
		return nil, false, nil
	}
	off += n

	if off > len(body) {
		return nil, false, nil
	}

	return &CallInfo{
		Program:    prog,
		Version:    vers,
		Procedure:  proc,
		AuthFlavor: flavor,
	}, true, nil
}

func parseReply(body []byte) (*ReplyInfo, bool, error) {
	if len(body) < 4 {
		return nil, false, nil
	}

	replyStat := binary.BigEndian.Uint32(body[0:4])
	if replyStat > replyDenied {
		return nil, false, nil
	}

	if replyStat == replyDenied {
		if !validateRejectedReply(body[4:]) {
			return nil, false, nil
		}
		return &ReplyInfo{Denied: true}, true, nil
	}

	// ACCEPTED reply: one opaque_auth at body[off], then accept_stat after off += n.
	off := 4
	verfFlavor, n, err := readOpaqueAuth(body[off:])
	if err != nil {
		return nil, false, err
	}
	if !validAuthFlavor(verfFlavor) {
		return nil, false, nil
	}
	off += n

	if len(body) < off+4 {
		return nil, false, nil
	}

	acceptStat := binary.BigEndian.Uint32(body[off : off+4])
	if acceptStat > 5 {
		return nil, false, nil
	}

	return &ReplyInfo{AcceptStat: acceptStat}, true, nil
}

// validateRejectedReply checks that a MSG_DENIED body contains a known reject_stat
// discriminant and enough XDR payload per RFC 5531.
func validateRejectedReply(body []byte) bool {
	if len(body) < 4 {
		return false
	}

	rejectStat := binary.BigEndian.Uint32(body[0:4])
	switch rejectStat {
	case rejectRPCMismatch:
		return len(body) >= 12
	case rejectAuthError:
		if len(body) < 8 {
			return false
		}
		authStat := binary.BigEndian.Uint32(body[4:8])
		return authStat <= maxAuthStat
	default:
		return false
	}
}

func readOpaqueAuth(b []byte) (flavor uint32, consumed int, err error) {
	if len(b) < 8 {
		return 0, 0, ErrTruncatedRecord
	}

	flavor = binary.BigEndian.Uint32(b[0:4])
	length := int(binary.BigEndian.Uint32(b[4:8]))
	if length < 0 {
		return 0, 0, ErrInvalidRPC
	}

	padded := (length + 3) &^ 3
	if len(b) < 8+padded {
		return 0, 0, ErrTruncatedRecord
	}

	return flavor, 8 + padded, nil
}

func validAuthFlavor(flavor uint32) bool {
	switch flavor {
	case authNull, authUnix, authShort, authDES, authKerb, authRSA, authRPCSECgss:
		return true
	default:
		return false
	}
}

func validProgram(prog uint32) bool {
	if prog == 0 || prog >= 0x40000000 {
		return false
	}
	if ProgramName(prog) != "" {
		return true
	}
	// Historic ONC program number block and registered high-range programs.
	return (prog >= 100000 && prog <= 101000) || (prog >= 0x20000000 && prog <= 0x2fffffff)
}

// ProcedureLabel returns the RPC method label for spans.
func ProcedureLabel(prog, proc uint32) string {
	if name := procedureName(prog, proc); name != "" {
		return name
	}
	return strconv.FormatUint(uint64(proc), 10)
}
