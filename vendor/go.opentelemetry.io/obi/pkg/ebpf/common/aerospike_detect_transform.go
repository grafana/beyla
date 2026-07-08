// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

// Aerospike native client protocol (proto version 2) parser.
//
// Only type-3 AS_MSG data frames produce spans. The protocol is
// one-request-one-response per connection (FIFO).
//
// Wire layout (all multi-byte integers big-endian):
//
//	proto header (8 bytes): version(1)=2, type(1), size(6)  // size = body length
//	as_msg header (22 bytes): header_sz(1)=22, info1(1), info2(1), info3(1),
//	    info4(1), result_code(1), generation(4), record_ttl(4), transaction_ttl(4),
//	    n_fields(2), n_ops(2)
//	field:  field_sz(4)=len(type+value), type(1), value(field_sz-1)
//	op:     op_sz(4), op(1), particle_type(1), version(1), name_sz(1), name, value

import (
	"encoding/binary"
	"strconv"
	"unsafe"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const (
	asProtoHeaderLen = 8
	asMsgHeaderLen   = 22
	asProtoVersion   = 2

	asTypeMessage = 3 // AS_MSG: the data protocol

	// info1 flags (read side)
	asInfo1Read   = 0x01
	asInfo1Batch  = 0x08
	asInfo1NoBins = 0x20 // GET_NO_BINS, used by exists

	// info2 flags (write side)
	asInfo2Write  = 0x01
	asInfo2Delete = 0x02

	// field type ids
	asFieldNamespace   = 0
	asFieldSet         = 1
	asFieldKey         = 2
	asFieldDigestRipe  = 4
	asFieldIndexNameLo = 21 // index-related fields span 21..26 (secondary-index query)
	asFieldIndexHi     = 26
	asFieldUDFLo       = 30 // UDF fields span 30..33
	asFieldUDFHi       = 33
	asFieldBatch       = 41 // batch (41) / batch-with-set (42)
	asFieldBatchSet    = 42

	// particle type ids (the 1-byte prefix on a field/bin value)
	asParticleString = 3

	// op type ids
	asOpWrite = 2
	asOpTouch = 11

	// largest declared proto body we will treat as plausibly Aerospike
	asMaxBodyLen = 128 * 1024 * 1024

	// status / result codes
	asResultKeyNotFound = 2

	asResultCodeOffset = asProtoHeaderLen + 5 // result_code: as_msg header byte 5
)

type aerospikeInfo struct {
	op        string
	namespace string
	set       string
	userKey   string
	batchSize int
}

// protoBodyLen decodes the 6-byte big-endian size field of a proto header.
func protoBodyLen(h []uint8) uint64 {
	var b [8]byte
	copy(b[2:], h[2:asProtoHeaderLen])
	return binary.BigEndian.Uint64(b[:])
}

// validProtoHeader reports whether the 8-byte slice is a plausible Aerospike
// type-3 AS_MSG proto header. Info/security/compressed frames don't produce spans
// so they are rejected here.
func validProtoHeader(h []uint8) bool {
	if len(h) < asProtoHeaderLen || h[0] != asProtoVersion || h[1] != asTypeMessage {
		return false
	}
	bodyLen := protoBodyLen(h)
	return bodyLen != 0 && bodyLen <= asMaxBodyLen
}

// asMsgIsRequest distinguishes a request from a response AS_MSG body. Requests
// always carry at least one read/batch/write intent bit; responses do not.
func asMsgIsRequest(info1, info2 uint8) bool {
	return info1&(asInfo1Read|asInfo1Batch) != 0 || info2&asInfo2Write != 0
}

// parseAerospikeRequest parses a type-3 AS_MSG request frame. Returns nil if the
// buffer is not a type-3 request (info/auth/compressed, a response, or malformed).
// Parsing is defensive: a short/truncated read stops the walk and returns what was
// decoded so far.
func parseAerospikeRequest(buf *largebuf.LargeBuffer) *aerospikeInfo {
	if buf == nil || buf.Len() < asProtoHeaderLen+asMsgHeaderLen {
		return nil
	}
	r := buf.NewReader()

	proto, err := r.ReadN(asProtoHeaderLen)
	if err != nil || !validProtoHeader(proto) {
		return nil
	}

	asm, err := r.ReadN(asMsgHeaderLen)
	if err != nil {
		return nil
	}
	// header_sz is a constant 22; checking it makes the (version==2, type==3,
	// header_sz==22, request-intent bits) signature strong enough to classify the
	// connection from a single frame without false positives.
	if asm[0] != asMsgHeaderLen {
		return nil
	}
	info1, info2 := asm[1], asm[2]
	if !asMsgIsRequest(info1, info2) {
		return nil
	}
	nFields := int(binary.BigEndian.Uint16(asm[18:20]))
	nOps := int(binary.BigEndian.Uint16(asm[20:22]))

	info := &aerospikeInfo{}
	hasDigest, hasIndex, hasUDF := parseAerospikeFields(&r, nFields, info)

	info.op = classifyAerospikeOp(info1, info2, &r, nOps, hasDigest, hasIndex, hasUDF)
	return info
}

// parseAerospikeFields walks the field section, filling namespace/set/key/batch
// size into info and reporting which marker fields (digest, secondary index, UDF)
// were seen. A truncated read (e.g. a scan/query partition list cut off at the
// capture boundary) stops the walk; the operation is still classified from the
// flags and the fields decoded before the cut.
func parseAerospikeFields(r *largebuf.LargeBufferReader, nFields int, info *aerospikeInfo) (hasDigest, hasIndex, hasUDF bool) {
fieldLoop:
	for i := 0; i < nFields; i++ {
		fsz, err := r.ReadU32BE()
		if err != nil || fsz < 1 {
			break
		}
		ftype, err := r.ReadU8()
		if err != nil {
			break
		}
		valLen := int(fsz) - 1
		switch {
		case ftype == asFieldNamespace:
			v, err := r.ReadN(valLen)
			if err != nil {
				break fieldLoop
			}
			info.namespace = string(v)
		case ftype == asFieldSet:
			v, err := r.ReadN(valLen)
			if err != nil {
				break fieldLoop
			}
			info.set = string(v)
		case ftype == asFieldKey:
			// value = 1-byte particle type + key bytes. Only string keys are
			// decoded; integer/blob keys would be binary and high-cardinality.
			v, err := r.ReadN(valLen)
			if err != nil {
				break fieldLoop
			}
			if valLen > 1 && v[0] == asParticleString {
				info.userKey = string(v[1:])
			}
		case ftype == asFieldBatch || ftype == asFieldBatchSet:
			// batch field value begins with a 4-byte operation count.
			if valLen >= 4 {
				n, err := r.ReadU32BE()
				if err != nil {
					break fieldLoop
				}
				info.batchSize = int(n)
				if r.Skip(valLen-4) != nil {
					break fieldLoop
				}
			} else if r.Skip(valLen) != nil {
				break fieldLoop
			}
		case ftype >= asFieldIndexNameLo && ftype <= asFieldIndexHi:
			hasIndex = true
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		case ftype >= asFieldUDFLo && ftype <= asFieldUDFHi:
			hasUDF = true
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		default:
			if ftype == asFieldDigestRipe {
				hasDigest = true
			}
			if r.Skip(valLen) != nil {
				break fieldLoop
			}
		}
	}
	return hasDigest, hasIndex, hasUDF
}

// classifyAerospikeOp derives the operation name from the info flags plus, for
// writes, the per-op type bytes (to separate PUT / TOUCH / OPERATE). The reader
// cursor must be positioned at the first op.
func classifyAerospikeOp(info1, info2 uint8, r *largebuf.LargeBufferReader, nOps int, hasDigest, hasIndex, hasUDF bool) string {
	switch {
	case hasUDF:
		return "UDF"
	case info1&asInfo1Batch != 0:
		return "BATCH"
	case info2&asInfo2Write != 0 && info2&asInfo2Delete != 0:
		return "DELETE"
	case info2&asInfo2Write != 0:
		return classifyAerospikeWrite(r, nOps)
	case info1&asInfo1Read != 0:
		return classifyAerospikeRead(info1, hasDigest, hasIndex)
	}
	return "UNKNOWN"
}

// classifyAerospikeRead separates QUERY (secondary index), SCAN (no digest, i.e.
// whole-namespace), EXISTS (GET_NO_BINS) and GET (single-record read).
func classifyAerospikeRead(info1 uint8, hasDigest, hasIndex bool) string {
	switch {
	case hasIndex:
		return "QUERY"
	case !hasDigest:
		return "SCAN"
	case info1&asInfo1NoBins != 0:
		return "EXISTS"
	default:
		return "GET"
	}
}

// classifyAerospikeWrite separates PUT (all writes), TOUCH (a lone touch op) and
// OPERATE (anything else: increment/append/CDT/mixed read+write) from the per-op
// type bytes.
func classifyAerospikeWrite(r *largebuf.LargeBufferReader, nOps int) string {
	allWrite := true
	allTouch := true
	count := 0
	for i := 0; i < nOps; i++ {
		opSz, err := r.ReadU32BE()
		if err != nil || opSz < 1 {
			break
		}
		opType, err := r.ReadU8()
		if err != nil {
			break
		}
		count++
		if opType != asOpWrite {
			allWrite = false
		}
		if opType != asOpTouch {
			allTouch = false
		}
		if r.Skip(int(opSz)-1) != nil {
			break
		}
	}
	switch {
	case count == 0:
		return "PUT"
	case allTouch:
		return "TOUCH"
	case allWrite:
		return "PUT"
	default:
		return "OPERATE"
	}
}

// aerospikeStatus reads the result_code from a response AS_MSG and maps it to a
// span status (0 = ok). KEY_NOT_FOUND is treated as a non-error miss.
func aerospikeStatus(buf *largebuf.LargeBuffer) (int, request.DBError) {
	if buf == nil || buf.Len() < asProtoHeaderLen+asMsgHeaderLen {
		return 0, request.DBError{}
	}
	version, err := buf.U8At(0)
	if err != nil || version != asProtoVersion {
		return 0, request.DBError{}
	}
	typ, err := buf.U8At(1)
	if err != nil || typ != asTypeMessage {
		return 0, request.DBError{}
	}
	resultCode, err := buf.U8At(asResultCodeOffset)
	if err != nil || resultCode == 0 || resultCode == asResultKeyNotFound {
		return 0, request.DBError{}
	}
	name := aerospikeResultName(resultCode)
	return 1, request.DBError{ErrorCode: name, Description: name}
}

func aerospikeResultName(code uint8) string {
	switch code {
	case 1:
		return "SERVER_ERROR"
	case 2:
		return "KEY_NOT_FOUND_ERROR"
	case 3:
		return "GENERATION_ERROR"
	case 4:
		return "PARAMETER_ERROR"
	case 5:
		return "KEY_EXISTS_ERROR"
	case 6:
		return "BIN_EXISTS_ERROR"
	case 8:
		return "SERVER_FULL"
	case 9:
		return "TIMEOUT"
	case 13:
		return "RECORD_TOO_BIG"
	case 14:
		return "KEY_BUSY"
	case 22:
		return "FORBIDDEN"
	default:
		return strconv.FormatUint(uint64(code), 10)
	}
}

func TCPToAerospikeToSpan(trace *TCPRequestInfo, info *aerospikeInfo, status int, dbError request.DBError) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0
	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	return request.Span{
		Type:         request.EventTypeAerospikeClient,
		Method:       info.op,
		Path:         info.set,
		Peer:         peer,
		PeerPort:     int(trace.ConnInfo.S_port),
		Host:         hostname,
		HostPort:     hostPort,
		RequestStart: int64(trace.StartMonotimeNs),
		Start:        int64(trace.StartMonotimeNs),
		End:          int64(trace.EndMonotimeNs),
		Status:       status,
		TraceID:      trace.Tp.TraceId,
		SpanID:       trace.Tp.SpanId,
		ParentSpanID: trace.Tp.ParentId,
		TraceFlags:   trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   app.PID(trace.Pid.HostPid),
			UserPID:   app.PID(trace.Pid.UserPid),
			Namespace: trace.Pid.Ns,
		},
		DBNamespace: info.namespace,
		DBSystem:    "aerospike",
		DBError:     dbError,
		Statement:   info.userKey,
		DBBatchSize: info.batchSize,
	}
}
