// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package winmd

import (
	"bytes"
	"fmt"
	"io"
)

// StringHeap provides access to #Strings heap as defined in §II.24.2.3.
type StringHeap []byte

// String extracts string from the string heap st at offset start.
func (sh StringHeap) String(start uint32) (String, error) {
	if int(start) >= len(sh) {
		return String{}, fmt.Errorf("offset %d is beyond the end of string heap", start)
	}
	length := bytes.IndexByte(sh[start:], '\x00')
	if length == -1 {
		return String{}, fmt.Errorf("offset %d is not null-terminated", start)
	}
	end := int(start) + length
	return String{start, sh[start:end:end]}, nil
}

// GUIDHeap provides access to the #GUID heap as defined in §II.24.2.5.
type GUIDHeap []byte

// GUID extracts the GUID from the guid heap gh at idx.
func (gh GUIDHeap) GUID(idx uint32) ([16]byte, error) {
	offset := int(idx * 16)
	if offset+16 > len(gh) {
		return [16]byte{}, fmt.Errorf("offset %d is beyond the end of the heap", offset)
	}
	var v [16]byte
	copy(v[:], gh[offset:])
	return v, nil
}

// USHeap provides access to the #US heap as defined in §II.24.2.4.
type USHeap []byte

// BlobHeap provides access to the #Blob heap as defined in §II.24.2.4.
type BlobHeap []byte

// Bytes extracts data from the blob heap bh at offset start.
func (bh BlobHeap) Bytes(start uint32) ([]byte, error) {
	if int(start) >= len(bh) {
		return nil, fmt.Errorf("offset %d is beyond the end of the heap", start)
	}
	size, n, err := decodeCompressedUint32(bh[start:])
	if err != nil {
		return nil, err
	}
	start += uint32(n)
	if int(uint32(start)+size) >= len(bh) {
		return nil, io.ErrUnexpectedEOF
	}
	return bh[start : uint32(start)+size : uint32(start)+size], nil
}

type heaps struct {
	strs  StringHeap
	blobs BlobHeap
	guids GUIDHeap
}
