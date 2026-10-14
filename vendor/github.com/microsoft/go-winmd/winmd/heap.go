// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"
)

// StringHeap provides access to #Strings heap as defined in §II.24.2.3.
// A heap obtained from [Metadata] is shared and must be treated as read-only.
type StringHeap []byte

// String returns the NUL-terminated UTF-8 string at byte offset start, excluding
// the terminator. The result shares sh's backing bytes. On error, it returns
// a zero String. It does not modify sh.
func (sh StringHeap) String(start uint32) (String, error) {
	if uint64(start) >= uint64(len(sh)) {
		return String{}, fmt.Errorf("offset %d is beyond the end of string heap", start)
	}
	length := bytes.IndexByte(sh[start:], '\x00')
	if length == -1 {
		return String{}, fmt.Errorf("offset %d is not null-terminated", start)
	}
	end := int(start) + length
	data := sh[start:end:end]
	if !utf8.Valid(data) {
		return String{}, fmt.Errorf("offset %d contains invalid UTF-8 in string heap", start)
	}
	return String{start, data}, nil
}

// GUIDHeap provides access to the #GUID heap as defined in §II.24.2.5.
// A heap obtained from [Metadata] is shared and must be treated as read-only.
type GUIDHeap []byte

// GUID returns a copy of the GUID at the zero-based entry index idx, not a
// byte offset or the one-based GUID index stored in a metadata column.
// On error, it returns a zero array. It does not modify gh.
func (gh GUIDHeap) GUID(idx uint32) ([16]byte, error) {
	offset := uint64(idx) * 16
	if offset+16 > uint64(len(gh)) {
		return [16]byte{}, fmt.Errorf("offset %d is beyond the end of the heap", offset)
	}
	var v [16]byte
	copy(v[:], gh[offset:offset+16])
	return v, nil
}

// USHeap provides access to the #US heap as defined in §II.24.2.4.
// A heap obtained from [Metadata] is shared and must be treated as read-only.
type USHeap []byte

// BlobHeap provides access to the #Blob heap as defined in §II.24.2.4.
// A heap obtained from [Metadata] is shared and must be treated as read-only.
type BlobHeap []byte

// Bytes returns the blob at byte offset start, excluding its length prefix.
// It does not modify bh. The result shares bh's backing bytes and has capacity
// equal to its length; copy it before modifying it when bh belongs to [Metadata].
// A successful empty blob is a non-nil, zero-length slice. On error, the result
// is nil. Unlike table-column decoding, offset zero is an ordinary heap offset,
// not a null-reference marker.
func (bh BlobHeap) Bytes(start uint32) ([]byte, error) {
	if uint64(start) >= uint64(len(bh)) {
		return nil, fmt.Errorf("offset %d is beyond the end of the heap", start)
	}
	data := bh[start:]
	size, n, err := DecodeCompressedUint32(data)
	if err != nil {
		return nil, err
	}
	data = data[n:]
	if uint64(size) > uint64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	return data[:size:size], nil
}

type heaps struct {
	strs  StringHeap
	blobs BlobHeap
	guids GUIDHeap
}
