// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"

	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
)

// Mirror bpf/shared/custom_span.h.
const (
	customSpanMaxArgs = 12
	customSpanStrLen  = 128
)

// CustomSpanRawEvent is wire-compatible with `struct custom_span_event`.
type CustomSpanRawEvent struct {
	Type        uint8
	Kind        uint8
	ArgCnt      uint8
	HasTraceCtx uint8
	PairKind    uint8
	TraceFlags  uint8
	_           [2]byte
	Cookie      uint64
	Timestamp   uint64
	GlobalPid   uint32
	GlobalTid   uint32
	NsPid       uint32
	NsTid       uint32
	PidNsID     uint32
	StackOffset uint32
	GPtr        uint64
	TraceID     [16]byte
	SpanID      [8]byte
	ID          [8]byte
	ArgKind     [customSpanMaxArgs]uint8
	ArgStrLen   [customSpanMaxArgs]uint16
	_           uint32
	ArgInt      [customSpanMaxArgs]uint64
	ArgStr      [customSpanMaxArgs][customSpanStrLen]byte
}

var ErrCustomSpanShortRecord = errors.New("custom_span: ringbuf record too short")

func DecodeCustomSpanEvent(raw []byte) (*CustomSpanRawEvent, error) {
	if len(raw) < binary.Size(CustomSpanRawEvent{}) {
		return nil, fmt.Errorf("%w: got %d bytes", ErrCustomSpanShortRecord, len(raw))
	}
	var ev CustomSpanRawEvent
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// FormatArgInt renders an integer arg per the user-declared type.
func FormatArgInt(val uint64, kind obiebpf.CustomSpanArgKind, signed bool, bytes int) string {
	if kind != obiebpf.CustomSpanArgInt {
		return ""
	}
	if signed {
		switch bytes {
		case 1:
			return strconv.Itoa(int(int8(val)))
		case 2:
			return strconv.Itoa(int(int16(val)))
		case 4:
			return strconv.Itoa(int(int32(val)))
		}
		return strconv.FormatInt(int64(val), 10)
	}
	return strconv.FormatUint(val, 10)
}

// TrimNUL returns buf truncated at hint (or the first NUL if hint == 0).
func TrimNUL(buf []byte, hint uint16) string {
	end := len(buf)
	if hint > 0 && int(hint) <= end {
		end = int(hint)
		if end > 0 && buf[end-1] == 0 {
			end--
		}
	} else {
		for i, b := range buf {
			if b == 0 {
				end = i
				break
			}
		}
	}
	return string(buf[:end])
}
