// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf // import "go.opentelemetry.io/obi/pkg/internal/largebuf"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// LargeBuffer assembles chunked eBPF ring-buffer events into a contiguous byte stream.
//
// # Storage
//
// Chunks are stored independently as [][]byte. Each [LargeBuffer.AppendChunk] call allocates
// exactly one new slice and records its header (pointer + length + capacity, 24 bytes) in the
// chunk index. No previously-written chunk data is ever reallocated or copied when new chunks
// arrive — contrast with a flat []byte whose backing array must be copied on every capacity
// growth.
//
// # Reading
//
// Use [LargeBuffer.NewReader] to create a [LargeBufferReader] positioned at byte 0, then call
// its cursor methods ([LargeBufferReader.ReadN], [LargeBufferReader.Peek], etc.) to parse the
// payload. Multiple independent readers can operate on the same buffer simultaneously.
//
// For random-access reads without a cursor, use [LargeBuffer.UnsafeViewAt],
// [LargeBuffer.CopyAt], and the scalar helpers (e.g. [LargeBuffer.U32BEAt]) directly on the
// buffer.
//
// # Ring-buffer memory safety
//
// eBPF ring-buffer records share kernel-mapped memory that is reclaimed on the next ReadInto
// call. [LargeBuffer.AppendChunk] always copies the provided data into a new Go-owned allocation,
// so no reference to ring-buffer memory is retained across event-loop iterations.
//
// [LargeBuffer.NewLargeBufferFrom] is the only exception: it wraps an existing slice without
// copying. It is safe only when the wrapped slice outlives all reads — use it exclusively for
// inline event buffers consumed within the same call frame.
type LargeBuffer struct {
	chunks  [][]byte
	total   int
	scratch []byte // used only by UnsafeViewAt for cross-chunk absolute-offset reads
}

// NewLargeBuffer returns an empty LargeBuffer ready to receive chunks.
func NewLargeBuffer() *LargeBuffer {
	return &LargeBuffer{}
}

// NewLargeBufferFrom wraps b as a single-chunk LargeBuffer without copying.
//
// The caller must ensure that b remains valid for the lifetime of all reads.
// Do NOT use this with ring-buffer memory that will be reclaimed across event-loop iterations.
// Safe use: inline event fields (e.g. event.Buf[:]) consumed within the same call frame.
func NewLargeBufferFrom(b []byte) *LargeBuffer {
	return &LargeBuffer{
		chunks: [][]byte{b},
		total:  len(b),
	}
}

// AppendChunk copies data into a new independently-allocated chunk.
func (lb *LargeBuffer) AppendChunk(data []byte) {
	chunk := make([]byte, len(data))
	copy(chunk, data)

	lb.chunks = append(lb.chunks, chunk)
	lb.total += len(data)
}

// Len returns the total number of bytes across all chunks.
func (lb *LargeBuffer) Len() int {
	return lb.total
}

// IsEmpty reports whether the buffer contains no bytes (Len() == 0).
func (lb *LargeBuffer) IsEmpty() bool {
	return lb.total == 0
}

// CloneBytes returns a freshly allocated copy of all chunks.
// The caller owns the returned slice — it is never shared with the LargeBuffer's
// internal storage.
func (lb *LargeBuffer) CloneBytes() []byte {
	if lb.total == 0 {
		return nil
	}

	out := make([]byte, lb.total)
	pos := 0

	for _, chunk := range lb.chunks {
		pos += copy(out[pos:], chunk)
	}

	return out
}

// Reset clears all chunks, returning the LargeBuffer to its zero value.
// The scratch buffer is retained to avoid re-allocation on the next use.
// Intended for future use with sync.Pool to allow instance reuse.
func (lb *LargeBuffer) Reset() {
	lb.chunks = lb.chunks[:0]
	lb.total = 0
}

// NewReader returns a new [LargeBufferReader] positioned at byte 0 of the buffer.
// The reader is returned by value; take its address (&r) when passing to functions
// that accept *LargeBufferReader or io.Reader.
// Multiple independent readers can operate on the same buffer simultaneously.
func (lb *LargeBuffer) NewReader() LargeBufferReader {
	return LargeBufferReader{lb: lb, end: -1}
}

// NewLimitedReader returns a [LargeBufferReader] positioned at offset whose reads are bounded
// to [offset, end). offset and end must satisfy 0 ≤ offset ≤ end ≤ Len().
//
// This is zero-copy and allocation-free: no new LargeBuffer is created. It is the preferred
// alternative to wrapping a sub-slice with [NewLargeBufferFrom] when only a window of the
// buffer needs to be parsed.
func (lb *LargeBuffer) NewLimitedReader(offset, end int) (LargeBufferReader, error) {
	if offset < 0 || offset > lb.total {
		return LargeBufferReader{}, fmt.Errorf("LargeBuffer.NewLimitedReader: offset %d out of range [0, %d]", offset, lb.total)
	}
	if end < offset || end > lb.total {
		return LargeBufferReader{}, fmt.Errorf("LargeBuffer.NewLimitedReader: end %d out of range [%d, %d]", end, offset, lb.total)
	}
	r := lb.NewReader()
	if offset > 0 {
		if err := r.Skip(offset); err != nil {
			return LargeBufferReader{}, err
		}
	}
	r.end = end
	return r, nil
}

// ── Absolute-offset access ────────────────────────────────────────────────────

// findChunk maps absOff (an absolute byte offset from the start of the buffer) to the chunk
// index and the byte offset within that chunk. Returns (-1, 0) when absOff is out of
// [0, lb.total). O(number of chunks); fast for the typical 1–3 chunk case.
func (lb *LargeBuffer) findChunk(absOff int) (int, int) {
	if absOff < 0 || absOff >= lb.total {
		return -1, 0
	}

	pos := 0

	for i, chunk := range lb.chunks {
		end := pos + len(chunk)
		if absOff < end {
			return i, absOff - pos
		}
		pos = end
	}

	return -1, 0
}

// UnsafeView returns a view over the entire buffer contents, equivalent to UnsafeViewAt(0, Len()).
//
// The returned slice MUST NOT be retained across the next UnsafeView or UnsafeViewAt call on the
// same buffer. Returns nil when the buffer is empty.
func (lb *LargeBuffer) UnsafeView() []byte {
	if lb.total == 0 {
		return nil
	}

	b, _ := lb.UnsafeViewAt(0, lb.total)

	return b
}

// UnsafeViewAt returns n bytes starting at absOff.
//
// Zero-copy path: when all n bytes lie within one chunk, a sub-slice of that chunk's backing
// array is returned — no allocation, no copy.
//
// Cross-chunk path: bytes are copied into the internal scratch buffer (grown as needed, never
// freed). The same scratch slice is reused on subsequent cross-chunk calls.
//
// The returned slice MUST NOT be retained across the next UnsafeViewAt call on the same buffer.
//
// Returns an error when the range [absOff, absOff+n) is out of [0, Len()).
func (lb *LargeBuffer) UnsafeViewAt(absOff, n int) ([]byte, error) {
	if n == 0 {
		return []byte{}, nil
	}

	if n < 0 || absOff < 0 || absOff+n > lb.total {
		return nil, fmt.Errorf("LargeBuffer.UnsafeViewAt: [%d, %d) out of range [0, %d)", absOff, absOff+n, lb.total)
	}

	ci, off := lb.findChunk(absOff)

	// Fast path: all bytes within one chunk — zero-copy.
	if off+n <= len(lb.chunks[ci]) {
		return lb.chunks[ci][off : off+n], nil
	}

	// Slow path: crosses chunk boundary — copy into reusable scratch.
	if cap(lb.scratch) < n {
		lb.scratch = make([]byte, n)
	}

	lb.scratch = lb.scratch[:n]

	for filled := 0; filled < n; {
		copied := copy(lb.scratch[filled:], lb.chunks[ci][off:])
		filled += copied
		ci++
		off = 0
	}

	return lb.scratch, nil
}

// CopyAt copies exactly len(dst) bytes starting at absolute offset absOff into dst.
//
// Works across chunk boundaries. The caller owns the result.
// Returns an error when the range [absOff, absOff+len(dst)) is out of [0, Len()).
func (lb *LargeBuffer) CopyAt(absOff int, dst []byte) error {
	n := len(dst)

	if n == 0 {
		return nil
	}

	if absOff < 0 || absOff+n > lb.total {
		return fmt.Errorf("LargeBuffer.CopyAt: [%d, %d) out of range [0, %d)", absOff, absOff+n, lb.total)
	}

	ci, off := lb.findChunk(absOff)

	for filled := 0; filled < n; {
		copied := copy(dst[filled:], lb.chunks[ci][off:])
		filled += copied
		ci++
		off = 0
	}

	return nil
}

// ── Scalar helpers ────────────────────────────────────────────────────────────
//
// Each helper reads a fixed-width integer at absOff.
// All delegate to UnsafeViewAt: zero-copy within a chunk, scratch-backed across boundaries.

// U8At reads a uint8 at absOff.
func (lb *LargeBuffer) U8At(absOff int) (uint8, error) {
	b, err := lb.UnsafeViewAt(absOff, 1)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

// U16BEAt reads a big-endian uint16 at absOff.
func (lb *LargeBuffer) U16BEAt(absOff int) (uint16, error) {
	b, err := lb.UnsafeViewAt(absOff, 2)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(b), nil
}

// U32BEAt reads a big-endian uint32 at absOff.
func (lb *LargeBuffer) U32BEAt(absOff int) (uint32, error) {
	b, err := lb.UnsafeViewAt(absOff, 4)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// U64BEAt reads a big-endian uint64 at absOff.
func (lb *LargeBuffer) U64BEAt(absOff int) (uint64, error) {
	b, err := lb.UnsafeViewAt(absOff, 8)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(b), nil
}

// I16BEAt reads a big-endian int16 at absOff.
func (lb *LargeBuffer) I16BEAt(absOff int) (int16, error) {
	v, err := lb.U16BEAt(absOff)

	return int16(v), err
}

// I32BEAt reads a big-endian int32 at absOff.
func (lb *LargeBuffer) I32BEAt(absOff int) (int32, error) {
	v, err := lb.U32BEAt(absOff)

	return int32(v), err
}

// I64BEAt reads a big-endian int64 at absOff.
func (lb *LargeBuffer) I64BEAt(absOff int) (int64, error) {
	v, err := lb.U64BEAt(absOff)

	return int64(v), err
}

// U16LEAt reads a little-endian uint16 at absOff.
func (lb *LargeBuffer) U16LEAt(absOff int) (uint16, error) {
	b, err := lb.UnsafeViewAt(absOff, 2)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint16(b), nil
}

// U32LEAt reads a little-endian uint32 at absOff.
func (lb *LargeBuffer) U32LEAt(absOff int) (uint32, error) {
	b, err := lb.UnsafeViewAt(absOff, 4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

// U64LEAt reads a little-endian uint64 at absOff.
func (lb *LargeBuffer) U64LEAt(absOff int) (uint64, error) {
	b, err := lb.UnsafeViewAt(absOff, 8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

// I16LEAt reads a little-endian int16 at absOff.
func (lb *LargeBuffer) I16LEAt(absOff int) (int16, error) {
	v, err := lb.U16LEAt(absOff)

	return int16(v), err
}

// I32LEAt reads a little-endian int32 at absOff.
func (lb *LargeBuffer) I32LEAt(absOff int) (int32, error) {
	v, err := lb.U32LEAt(absOff)

	return int32(v), err
}

// I64LEAt reads a little-endian int64 at absOff.
func (lb *LargeBuffer) I64LEAt(absOff int) (int64, error) {
	v, err := lb.U64LEAt(absOff)

	return int64(v), err
}

// IndexByteAt returns the absolute byte offset of the first occurrence of c
// at or after absOff, or -1 if c is not found in [absOff, Len()).
func (lb *LargeBuffer) IndexByteAt(absOff int, c byte) int {
	if absOff < 0 || absOff >= lb.total {
		return -1
	}

	ci, off := lb.findChunk(absOff)
	abs := absOff

	for ci < len(lb.chunks) {
		chunk := lb.chunks[ci][off:]
		if idx := bytes.IndexByte(chunk, c); idx >= 0 {
			return abs + idx
		}
		abs += len(chunk)
		ci++
		off = 0
	}

	return -1
}

// ── LargeBufferReader ─────────────────────────────────────────────────────────

// LargeBufferReader provides cursor-based sequential access to a [LargeBuffer].
//
// Create with [LargeBuffer.NewReader]. Multiple independent readers can operate on the same
// buffer simultaneously — each reader maintains its own cursor and scratch buffer.
//
// ReadN returns the next n bytes and advances the cursor.
// When all n bytes lie within the current chunk, a sub-slice of that chunk's backing array is
// returned (zero allocation, zero copy). When n crosses a chunk boundary the internal scratch
// buffer is reused (one copy, no heap allocation after the first cross-boundary read). The
// returned slice must NOT be retained across the next ReadN or Read call.
//
// LargeBufferReader implements [io.Reader] for use with bufio.NewReader and stream-oriented
// parsers such as net/http.
type LargeBufferReader struct {
	lb      *LargeBuffer
	rchunk  int // index of the current read chunk
	roff    int // byte offset within lb.chunks[rchunk]
	end     int // absolute end bound; -1 means no limit (reads to lb.total)
	scratch []byte
}

// Reset repositions this reader to byte 0.
// For readers created with [LargeBuffer.NewLimitedReader], the end bound is preserved —
// subsequent reads are still limited to [0, end). Use [LargeBuffer.NewReader] if you need
// a fresh unlimited reader.
func (r *LargeBufferReader) Reset() {
	r.rchunk = 0
	r.roff = 0
}

// ReadOffset returns the current cursor position as an absolute byte offset from the start of
// the buffer.
func (r *LargeBufferReader) ReadOffset() int {
	pos := r.roff
	for i := range r.rchunk {
		pos += len(r.lb.chunks[i])
	}
	return pos
}

// Remaining returns the number of unread bytes from the cursor to the end bound.
// For readers created with [LargeBuffer.NewLimitedReader] the end bound is the limit
// passed at construction; for ordinary readers it is [LargeBuffer.Len].
func (r *LargeBufferReader) Remaining() int {
	effectiveEnd := r.lb.total
	if r.end >= 0 {
		effectiveEnd = r.end
	}
	return effectiveEnd - r.ReadOffset()
}

// BaseOffset always returns 0. Provided for API symmetry with ReadOffset.
func (r *LargeBufferReader) BaseOffset() int {
	return 0
}

// ── Cursor-based access ───────────────────────────────────────────────────────

// ReadN returns exactly n bytes starting at the current read position and advances the cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk's
// backing array is returned — no allocation, no copy.
//
// Cross-chunk path: bytes are copied into the internal scratch buffer (grown as needed, never
// freed). The same scratch slice is reused on subsequent cross-chunk calls.
//
// The returned slice MUST NOT be retained across the next ReadN or Read call.
func (r *LargeBufferReader) ReadN(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}

	if n > r.Remaining() {
		return nil, fmt.Errorf("LargeBuffer.ReadN: requested %d bytes but only %d remaining", n, r.Remaining())
	}

	// Fast path: all bytes within the current chunk — zero allocation, zero copy.
	if r.rchunk < len(r.lb.chunks) && r.roff+n <= len(r.lb.chunks[r.rchunk]) {
		s := r.lb.chunks[r.rchunk][r.roff : r.roff+n]

		r.roff += n

		if r.roff == len(r.lb.chunks[r.rchunk]) {
			r.rchunk++
			r.roff = 0
		}

		return s, nil
	}

	// Slow path: copy across chunk boundaries into reusable scratch.
	if cap(r.scratch) < n {
		r.scratch = make([]byte, n)
	}

	r.scratch = r.scratch[:n]
	r.copyN(r.scratch)

	return r.scratch, nil
}

// Peek returns the next n bytes without advancing the read cursor.
//
// Zero-copy path: when all n bytes lie within the current chunk, a sub-slice of that chunk is
// returned with no allocation.
//
// Cross-chunk path: copies into the internal scratch buffer (same reuse semantics as ReadN).
//
// The returned slice MUST NOT be retained across the next ReadN or Read call.
func (r *LargeBufferReader) Peek(n int) ([]byte, error) {
	if n == 0 {
		return nil, nil
	}

	if n > r.Remaining() {
		return nil, fmt.Errorf("LargeBuffer.Peek: requested %d bytes but only %d remaining", n, r.Remaining())
	}

	// Fast path: within current chunk — return sub-slice directly.
	if r.rchunk < len(r.lb.chunks) && r.roff+n <= len(r.lb.chunks[r.rchunk]) {
		return r.lb.chunks[r.rchunk][r.roff : r.roff+n], nil
	}

	// Slow path: copy into scratch, then restore cursor position.
	savedChunk, savedOff := r.rchunk, r.roff

	if cap(r.scratch) < n {
		r.scratch = make([]byte, n)
	}
	r.scratch = r.scratch[:n]
	r.copyN(r.scratch)

	r.rchunk, r.roff = savedChunk, savedOff

	return r.scratch, nil
}

// Skip advances the read cursor by n bytes without copying any data.
func (r *LargeBufferReader) Skip(n int) error {
	if n > r.Remaining() {
		return fmt.Errorf("LargeBuffer.Skip: requested %d bytes but only %d remaining", n, r.Remaining())
	}

	for n > 0 {
		avail := len(r.lb.chunks[r.rchunk]) - r.roff

		if n < avail {
			r.roff += n
			return nil
		}

		n -= avail
		r.rchunk++
		r.roff = 0
	}

	return nil
}

// Read implements [io.Reader]. Fills p with up to len(p) bytes from the current read position,
// clamped to the reader's end bound (see [LargeBuffer.NewLimitedReader]).
//
// Returns (n, nil) when bytes were read but the cursor has not yet reached the end.
// Returns (0, io.EOF) when the cursor is already at the end of the buffer.
// Per the io.Reader contract, may return (n, nil) even when the last byte was just read;
// the subsequent call returns (0, io.EOF).
func (r *LargeBufferReader) Read(p []byte) (int, error) {
	maxRead := r.Remaining()
	if maxRead == 0 {
		return 0, io.EOF
	}
	if len(p) > maxRead {
		p = p[:maxRead]
	}

	n := 0
	for n < len(p) && r.rchunk < len(r.lb.chunks) {
		src := r.lb.chunks[r.rchunk][r.roff:]
		copied := copy(p[n:], src)

		n += copied
		r.roff += copied

		if r.roff == len(r.lb.chunks[r.rchunk]) {
			r.rchunk++
			r.roff = 0
		}
	}

	return n, nil
}

// Bytes returns the unread portion of the buffer (from the current read cursor to the end)
// without advancing the cursor — analogous to [bytes.Buffer.Bytes].
//
// Zero-copy path: when all remaining bytes lie within the current chunk, a sub-slice of that
// chunk's backing array is returned with no allocation.
//
// Cross-chunk path: copies into the internal scratch buffer (same reuse semantics as ReadN).
// The returned slice MUST NOT be retained across the next ReadN, Read, or Bytes call.
//
// Returns nil when there are no unread bytes remaining (Remaining() == 0).
func (r *LargeBufferReader) Bytes() []byte {
	rem := r.Remaining()

	if rem == 0 {
		return nil
	}

	b, _ := r.Peek(rem)

	return b
}

// ── Cursor-based scalar helpers ───────────────────────────────────────────────
//
// Each helper reads a fixed-width integer at the current cursor position and advances it.
// All delegate to ReadN: zero-copy within a chunk, scratch-backed across boundaries.

// ReadU8 reads a uint8 at the current cursor position.
func (r *LargeBufferReader) ReadU8() (uint8, error) {
	b, err := r.ReadN(1)
	if err != nil {
		return 0, err
	}

	return b[0], nil
}

// ReadU16BE reads a big-endian uint16 at the current cursor position.
func (r *LargeBufferReader) ReadU16BE() (uint16, error) {
	b, err := r.ReadN(2)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint16(b), nil
}

// ReadI16BE reads a big-endian int16 at the current cursor position.
func (r *LargeBufferReader) ReadI16BE() (int16, error) {
	v, err := r.ReadU16BE()

	return int16(v), err
}

// ReadU32BE reads a big-endian uint32 at the current cursor position.
func (r *LargeBufferReader) ReadU32BE() (uint32, error) {
	b, err := r.ReadN(4)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b), nil
}

// ReadI32BE reads a big-endian int32 at the current cursor position.
func (r *LargeBufferReader) ReadI32BE() (int32, error) {
	v, err := r.ReadU32BE()

	return int32(v), err
}

// ReadU64BE reads a big-endian uint64 at the current cursor position.
func (r *LargeBufferReader) ReadU64BE() (uint64, error) {
	b, err := r.ReadN(8)
	if err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint64(b), nil
}

// ReadI64BE reads a big-endian int64 at the current cursor position.
func (r *LargeBufferReader) ReadI64BE() (int64, error) {
	v, err := r.ReadU64BE()

	return int64(v), err
}

// ReadU16LE reads a little-endian uint16 at the current cursor position.
func (r *LargeBufferReader) ReadU16LE() (uint16, error) {
	b, err := r.ReadN(2)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint16(b), nil
}

// ReadI16LE reads a little-endian int16 at the current cursor position.
func (r *LargeBufferReader) ReadI16LE() (int16, error) {
	v, err := r.ReadU16LE()

	return int16(v), err
}

// ReadU32LE reads a little-endian uint32 at the current cursor position.
func (r *LargeBufferReader) ReadU32LE() (uint32, error) {
	b, err := r.ReadN(4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

// ReadI32LE reads a little-endian int32 at the current cursor position.
func (r *LargeBufferReader) ReadI32LE() (int32, error) {
	v, err := r.ReadU32LE()

	return int32(v), err
}

// ReadU64LE reads a little-endian uint64 at the current cursor position.
func (r *LargeBufferReader) ReadU64LE() (uint64, error) {
	b, err := r.ReadN(8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

// ReadI64LE reads a little-endian int64 at the current cursor position.
func (r *LargeBufferReader) ReadI64LE() (int64, error) {
	v, err := r.ReadU64LE()

	return int64(v), err
}

// IndexByte returns the number of bytes from the current read position to the first occurrence
// of c in the remaining bytes (bounded by the reader's end), or -1 if c is not found.
func (r *LargeBufferReader) IndexByte(c byte) int {
	absOff := r.ReadOffset()
	absIdx := r.lb.IndexByteAt(absOff, c)
	if absIdx < 0 {
		return -1
	}
	if r.end >= 0 && absIdx >= r.end {
		return -1
	}
	return absIdx - absOff
}

// ReadCStr reads bytes up to the next null terminator, advances the cursor past the null,
// and returns the bytes before it. Zero-copy when the null byte lies within the current chunk.
// Returns an error if no null terminator is found in the remaining bytes.
func (r *LargeBufferReader) ReadCStr() ([]byte, error) {
	n := r.IndexByte(0)
	if n < 0 {
		return nil, errors.New("LargeBuffer.ReadCStr: no null terminator found")
	}

	b, err := r.ReadN(n)
	if err != nil {
		return nil, err
	}

	// Skip the null terminator. IndexByte(0) confirmed it exists and ReadN(n)
	// left the cursor exactly there, so this must succeed.
	if err = r.Skip(1); err != nil {
		return nil, fmt.Errorf("LargeBuffer.ReadCStr: failed to skip null terminator: %w", err)
	}

	return b, nil
}

// copyN copies exactly len(dst) bytes from the current read position into dst, advancing the
// cursor. Assumes the caller has already verified that len(dst) <= r.Remaining().
func (r *LargeBufferReader) copyN(dst []byte) {
	filled := 0

	for filled < len(dst) {
		src := r.lb.chunks[r.rchunk][r.roff:]
		copied := copy(dst[filled:], src)

		filled += copied
		r.roff += copied

		if r.roff == len(r.lb.chunks[r.rchunk]) {
			r.rchunk++
			r.roff = 0
		}
	}
}
