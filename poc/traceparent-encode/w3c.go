package tpencode

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	W3CValueLen     = 55
	TraceIDBytes    = 16
	SpanIDBytes     = 8
	TCPOptionKind   = 25
	TCPOptionBytes  = 2 + TraceIDBytes + SpanIDBytes // kind + len + ids = 26
	TCPOptionsMax   = 40
	// Beyla TRACE_PARENT_HEADER_LEN = 13 + 55 = 68 (no CRLF). TP_SIZE includes "\r\n" = 70.
	HTTP1ScanLen    = 13 + W3CValueLen
	HTTP1WireLen    = 13 + W3CValueLen + 2
	HPACKValueLenTP = 55 // Beyla k_hpack_value_len_tp
)

// Header is a parsed W3C traceparent value.
type Header struct {
	Version byte
	TraceID [TraceIDBytes]byte
	SpanID  [SpanIDBytes]byte
	Flags   byte
	Extra   string // bytes after the 4th field, if any
}

func (h Header) String() string {
	return Format(h)
}

func Format(h Header) string {
	var b strings.Builder
	b.Grow(W3CValueLen + len(h.Extra) + 1)
	fmt.Fprintf(&b, "%02x-%s-%s-%02x", h.Version, hex.EncodeToString(h.TraceID[:]), hex.EncodeToString(h.SpanID[:]), h.Flags)
	if h.Extra != "" {
		b.WriteByte('-')
		b.WriteString(h.Extra)
	}
	return b.String()
}

// Parse splits a traceparent value at dashes without enforcing version-00 rules.
func Parse(s string) (Header, error) {
	var h Header
	parts := strings.SplitN(s, "-", 5)
	if len(parts) < 4 {
		return h, fmt.Errorf("need 4 fields, got %d", len(parts))
	}
	if len(parts[0]) != 2 || len(parts[1]) != 32 || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return h, fmt.Errorf("wrong field widths: %v", []int{len(parts[0]), len(parts[1]), len(parts[2]), len(parts[3])})
	}
	if err := decodeByte(parts[0], &h.Version); err != nil {
		return h, err
	}
	tb, err := hex.DecodeString(parts[1])
	if err != nil || len(tb) != TraceIDBytes {
		return h, fmt.Errorf("trace-id: %w", err)
	}
	copy(h.TraceID[:], tb)
	sb, err := hex.DecodeString(parts[2])
	if err != nil || len(sb) != SpanIDBytes {
		return h, fmt.Errorf("span-id: %w", err)
	}
	copy(h.SpanID[:], sb)
	if err := decodeByte(parts[3], &h.Flags); err != nil {
		return h, err
	}
	if len(parts) == 5 {
		h.Extra = parts[4]
	}
	return h, nil
}

func decodeByte(s string, dst *byte) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 1 {
		return fmt.Errorf("hex byte %q: %w", s, err)
	}
	*dst = b[0]
	return nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// W3CValid reports whether s is a legal version-00 traceparent (exactly 55 chars).
func W3CValid(s string) error {
	if len(s) != W3CValueLen {
		return fmt.Errorf("length %d != %d", len(s), W3CValueLen)
	}
	h, err := Parse(s)
	if err != nil {
		return err
	}
	if h.Version != 0 {
		return fmt.Errorf("version %02x != 00", h.Version)
	}
	if h.Extra != "" {
		return fmt.Errorf("version 00 forbids extra fields")
	}
	if allZero(h.TraceID[:]) {
		return fmt.Errorf("trace-id all zero")
	}
	if allZero(h.SpanID[:]) {
		return fmt.Errorf("span-id all zero")
	}
	parts := strings.Split(s, "-")
	for i, p := range parts {
		if !isLowerHex(p) {
			return fmt.Errorf("field %d not lowercase hex", i)
		}
	}
	return nil
}

// OTelExtract mirrors go.opentelemetry.io/otel/propagation.TraceContext.extract
// from otel v1.46.0 (vendor/go.opentelemetry.io/otel/propagation/trace_context.go).
//
// Version 00: extra fields or flags > 3 reject the header.
// Version 01-fe: extra fields are ignored; IDs are still extracted.
func OTelExtract(s string) (Header, bool) {
	h := s
	var ver [1]byte
	if !otelExtractPart(ver[:], &h, 2) {
		return Header{}, false
	}
	version := int(ver[0])
	if version > 254 {
		return Header{}, false
	}
	var out Header
	out.Version = ver[0]
	if !otelExtractPart(out.TraceID[:], &h, 32) {
		return Header{}, false
	}
	if !otelExtractPart(out.SpanID[:], &h, 16) {
		return Header{}, false
	}
	var opts [1]byte
	if !otelExtractPart(opts[:], &h, 2) {
		return Header{}, false
	}
	if version == 0 && (h != "" || opts[0] > 3) {
		return Header{}, false
	}
	out.Flags = opts[0] & 0x03 // FlagsSampled | FlagsRandom
	out.Extra = strings.TrimPrefix(h, "-")
	if allZero(out.TraceID[:]) || allZero(out.SpanID[:]) {
		return Header{}, false
	}
	return out, true
}

func otelExtractPart(dst []byte, h *string, n int) bool {
	part, left, _ := strings.Cut(*h, "-")
	*h = left
	if len(part) != n {
		return false
	}
	for _, c := range part {
		if c >= 'A' && c <= 'F' {
			return false
		}
	}
	b, err := hex.DecodeString(part)
	if err != nil || len(b) != n/2 {
		return false
	}
	copy(dst, b)
	return true
}

// OTelInject mirrors TraceContext.Inject: always version 00, flags masked to 0x03,
// extra fields dropped, parent-id taken from the supplied span.
func OTelInject(in Header) string {
	out := Header{
		Version: 0,
		TraceID: in.TraceID,
		SpanID:  in.SpanID,
		Flags:   in.Flags & 0x03,
	}
	return Format(out)
}

// BeylaHTTP1WouldSee reports whether Beyla's is_traceparent + fixed-offset decode
// would recover the IDs. The BPF matcher only checks the "traceparent: " prefix
// and then reads 55 bytes at a fixed layout; extra suffix after those 55 is ignored.
func BeylaHTTP1WouldSee(value string) bool {
	if len(value) < W3CValueLen {
		return false
	}
	_, err := Parse(value[:W3CValueLen])
	return err == nil
}
