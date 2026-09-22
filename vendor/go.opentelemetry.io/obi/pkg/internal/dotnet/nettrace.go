// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	fastSerializationNullReference      byte = 1
	fastSerializationBeginPrivateObject byte = 5
	fastSerializationEndObject          byte = 6
	// maximumNetTraceBlockSize bounds decoder memory independently of the session buffer.
	maximumNetTraceBlockSize = 16 * 1024 * 1024
)

// Compressed event header flags encode field presence and event ordering.
const (
	netTraceMetadataIDFlag byte = 1 << iota
	netTraceCaptureSequenceFlag
	netTraceThreadIDFlag
	netTraceStackIDFlag
	netTraceActivityIDFlag
	netTraceRelatedActivityIDFlag
	netTraceSortedFlag
	netTracePayloadSizeFlag
)

// netTraceReader tracks the absolute stream offset used for block alignment.
// It must wrap the stream before the NetTrace preamble is read.
type netTraceReader struct {
	reader io.Reader
	offset int64
	block  []byte
}

// readNetTraceBlock reads a data block after the preamble. The returned payload
// shares the reader's reusable buffer and is valid until the next block read.
func readNetTraceBlock(reader *netTraceReader) (netTraceObjectHeader, []byte, error) {
	header, err := readNetTraceObjectHeader(reader)
	if err != nil {
		return netTraceObjectHeader{}, nil, err
	}
	if header.EndOfStream {
		return header, nil, nil
	}
	switch header.Name {
	case "EventBlock", "MetadataBlock", "StackBlock", "SPBlock":
	default:
		return netTraceObjectHeader{}, nil, fmt.Errorf("unsupported NetTrace block type: %q", header.Name)
	}
	if header.Version < 0 || header.Version > 2 || header.MinimumVersion < 0 || header.MinimumVersion > header.Version {
		return netTraceObjectHeader{}, nil, fmt.Errorf("unsupported NetTrace block version: %+v", header)
	}
	var size int32
	if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
		return netTraceObjectHeader{}, nil, fmt.Errorf("reading NetTrace block size: %w", err)
	}
	if size < 0 || size > maximumNetTraceBlockSize {
		return netTraceObjectHeader{}, nil, fmt.Errorf("invalid NetTrace block size: %d", size)
	}

	const alignment = 4
	paddingSize := (alignment - reader.offset%alignment) % alignment
	var padding [alignment - 1]byte
	if _, err := io.ReadFull(reader, padding[:paddingSize]); err != nil {
		return netTraceObjectHeader{}, nil, fmt.Errorf("reading NetTrace block padding: %w", err)
	}
	if int(size) > cap(reader.block) {
		reader.block = make([]byte, size)
	}
	reader.block = reader.block[:size]
	if _, err := io.ReadFull(reader, reader.block); err != nil {
		return netTraceObjectHeader{}, nil, fmt.Errorf("reading NetTrace block payload: %w", err)
	}
	var tag [1]byte
	if _, err := io.ReadFull(reader, tag[:]); err != nil {
		return netTraceObjectHeader{}, nil, fmt.Errorf("reading NetTrace block end tag: %w", err)
	}
	if tag[0] != fastSerializationEndObject {
		return netTraceObjectHeader{}, nil, fmt.Errorf("invalid NetTrace block end tag: %d", tag[0])
	}
	return header, reader.block, nil
}

// newNetTraceReader buffers stream reads while tracking only bytes consumed by
// the decoder, so read-ahead preserves block alignment calculations.
func newNetTraceReader(reader io.Reader) *netTraceReader {
	return &netTraceReader{reader: bufio.NewReader(reader)}
}

// Read counts bytes returned by the underlying reader, including bytes returned
// together with an error.
func (r *netTraceReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	r.offset += int64(n)
	return n, err
}

type netTraceObjectHeader struct {
	Name           string
	Version        int32
	MinimumVersion int32
	EndOfStream    bool
}

// readNetTraceEventBlockHeader reads the compression flag shared by .NET 8 event
// and metadata blocks, then skips the timestamp bounds and any header extension.
func readNetTraceEventBlockHeader(reader *bytes.Reader) (bool, error) {
	var header struct {
		Size  uint16
		Flags uint16
	}
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return false, fmt.Errorf("reading NetTrace event block header: %w", err)
	}
	const minimumHeaderSize = 2 + 2 + 8 + 8 // Size, flags, and two timestamp bounds.
	if header.Size < minimumHeaderSize {
		return false, fmt.Errorf("invalid NetTrace event block header size: %d", header.Size)
	}
	remaining := int(header.Size) - binary.Size(header)
	if remaining > reader.Len() {
		return false, fmt.Errorf("reading NetTrace event block header: %w", io.ErrUnexpectedEOF)
	}
	const headerCompression uint16 = 1
	if header.Flags & ^headerCompression != 0 {
		return false, fmt.Errorf("unsupported NetTrace event block flags: %#x", header.Flags)
	}
	if _, err := reader.Seek(int64(remaining), io.SeekCurrent); err != nil {
		return false, fmt.Errorf("skipping NetTrace event block header: %w", err)
	}
	return header.Flags&headerCompression != 0, nil
}

type netTraceInfo struct {
	SystemTime      [8]uint16
	SyncTimeQPC     int64
	QPCFrequency    int64
	PointerSize     int32
	ProcessID       int32
	ProcessorCount  int32
	CPUSamplingRate int32
}

type netTraceEventHeader struct {
	MetadataID        uint32
	SequenceNumber    uint32
	ThreadID          uint64
	CaptureThreadID   uint64
	CaptureProcessor  uint32
	StackID           uint32
	Timestamp         int64
	ActivityID        [16]byte
	RelatedActivityID [16]byte
	PayloadSize       uint32
	Sorted            bool
}

// readNetTraceCompressedEventHeader applies .NET 8 header deltas to the previous
// event in this block. Callers start each block with a zero header.
func readNetTraceCompressedEventHeader(reader *bytes.Reader, previous netTraceEventHeader) (netTraceEventHeader, error) {
	flags, err := reader.ReadByte()
	if err != nil {
		return netTraceEventHeader{}, fmt.Errorf("reading compressed NetTrace flags: %w", err)
	}
	// Keep the first decoding error and bound values before narrowing to uint32.
	readNumber := func(name string, bits int) uint64 {
		if err != nil {
			return 0
		}
		var value uint64
		value, err = binary.ReadUvarint(reader)
		if err != nil {
			err = fmt.Errorf("reading compressed NetTrace %s: %w", name, err)
			return 0
		}
		if bits == 32 && value > uint64(^uint32(0)) {
			err = fmt.Errorf("compressed NetTrace %s exceeds uint32: %d", name, value)
			return 0
		}
		return value
	}
	header := previous
	if flags&netTraceMetadataIDFlag != 0 {
		header.MetadataID = uint32(readNumber("metadata ID", 32))
	}
	if flags&netTraceCaptureSequenceFlag != 0 {
		header.SequenceNumber += uint32(readNumber("sequence delta", 32)) + 1
		header.CaptureThreadID = readNumber("capture thread ID", 64)
		header.CaptureProcessor = uint32(readNumber("capture processor", 32))
	} else if header.MetadataID != 0 {
		// NetTrace implicitly advances non-metadata events by one when the delta is omitted.
		// https://github.com/microsoft/perfview/blob/main/src/TraceEvent/EventPipe/NetTraceFormat_v5.md#header-compression
		header.SequenceNumber++
	}
	if flags&netTraceThreadIDFlag != 0 {
		header.ThreadID = readNumber("thread ID", 64)
	}
	if flags&netTraceStackIDFlag != 0 {
		header.StackID = uint32(readNumber("stack ID", 32))
	}
	header.Timestamp += int64(readNumber("timestamp delta", 64))
	if err != nil {
		return netTraceEventHeader{}, err
	}
	if flags&netTraceActivityIDFlag != 0 {
		if _, err := io.ReadFull(reader, header.ActivityID[:]); err != nil {
			return netTraceEventHeader{}, fmt.Errorf("reading compressed NetTrace activity ID: %w", err)
		}
	}
	if flags&netTraceRelatedActivityIDFlag != 0 {
		if _, err := io.ReadFull(reader, header.RelatedActivityID[:]); err != nil {
			return netTraceEventHeader{}, fmt.Errorf("reading compressed NetTrace related activity ID: %w", err)
		}
	}
	header.Sorted = flags&netTraceSortedFlag != 0
	if flags&netTracePayloadSizeFlag != 0 {
		header.PayloadSize = uint32(readNumber("payload size", 32))
	}
	if err != nil {
		return netTraceEventHeader{}, err
	}
	if uint64(header.PayloadSize) > uint64(reader.Len()) {
		return netTraceEventHeader{}, fmt.Errorf("invalid NetTrace event payload size: %d", header.PayloadSize)
	}
	return header, nil
}

// readNetTracePreamble reads the stream signatures and initial Trace object,
// leaving the reader at the first data block.
func readNetTracePreamble(reader io.Reader) (netTraceInfo, error) {
	if err := readNetTraceMagic(reader); err != nil {
		return netTraceInfo{}, err
	}
	if err := readFastSerializationHeader(reader); err != nil {
		return netTraceInfo{}, err
	}
	header, err := readNetTraceObjectHeader(reader)
	if err != nil {
		return netTraceInfo{}, err
	}
	return readNetTraceInfo(reader, header)
}

// readNetTraceInfo reads the fixed-size Trace payload and its closing tag.
// .NET 8 uses NetTrace format version 4; QPCFrequency gives clock ticks per second.
func readNetTraceInfo(reader io.Reader, header netTraceObjectHeader) (netTraceInfo, error) {
	if header.EndOfStream || header.Name != "Trace" || header.Version != 4 ||
		header.MinimumVersion < 0 || header.MinimumVersion > header.Version {
		return netTraceInfo{}, fmt.Errorf("unsupported NetTrace Trace header: %+v", header)
	}
	var info netTraceInfo
	if err := binary.Read(reader, binary.LittleEndian, &info); err != nil {
		return netTraceInfo{}, fmt.Errorf("reading NetTrace Trace payload: %w", err)
	}
	if info.QPCFrequency <= 0 {
		return netTraceInfo{}, fmt.Errorf("invalid NetTrace clock frequency: %d", info.QPCFrequency)
	}
	if info.PointerSize != 4 && info.PointerSize != 8 {
		return netTraceInfo{}, fmt.Errorf("invalid NetTrace pointer size: %d", info.PointerSize)
	}
	var tag [1]byte
	if _, err := io.ReadFull(reader, tag[:]); err != nil {
		return netTraceInfo{}, fmt.Errorf("reading NetTrace Trace end tag: %w", err)
	}
	if tag[0] != fastSerializationEndObject {
		return netTraceInfo{}, fmt.Errorf("invalid NetTrace Trace end tag: %d", tag[0])
	}
	return info, nil
}

// readNetTraceMagic consumes the NetTrace signature preceding the serialization
// header. The trace's format version is encoded separately.
func readNetTraceMagic(reader io.Reader) error {
	const magic = "Nettrace"
	var signature [len(magic)]byte
	if _, err := io.ReadFull(reader, signature[:]); err != nil {
		return fmt.Errorf("reading NetTrace signature: %w", err)
	}
	if string(signature[:]) != magic {
		return fmt.Errorf("invalid NetTrace signature: %q", signature[:])
	}
	return nil
}

// readFastSerializationHeader consumes the length-prefixed serialization marker
// used by .NET 8 NetTrace streams, leaving the reader at the first object.
func readFastSerializationHeader(reader io.Reader) error {
	const marker = "!FastSerialization.1"
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return fmt.Errorf("reading FastSerialization marker length: %w", err)
	}
	if length != uint32(len(marker)) {
		return fmt.Errorf("invalid FastSerialization marker length: %d", length)
	}

	var signature [len(marker)]byte
	if _, err := io.ReadFull(reader, signature[:]); err != nil {
		return fmt.Errorf("reading FastSerialization marker: %w", err)
	}
	if string(signature[:]) != marker {
		return fmt.Errorf("invalid FastSerialization marker: %q", signature[:])
	}
	return nil
}

// readNetTraceObjectHeader reads the type description preceding an object's
// payload. A null reference marks the explicit end of the NetTrace stream.
func readNetTraceObjectHeader(reader io.Reader) (netTraceObjectHeader, error) {
	var tag [1]byte
	if _, err := io.ReadFull(reader, tag[:]); err != nil {
		return netTraceObjectHeader{}, fmt.Errorf("reading NetTrace object tag: %w", err)
	}
	if tag[0] == fastSerializationNullReference {
		return netTraceObjectHeader{EndOfStream: true}, nil
	}
	if tag[0] != fastSerializationBeginPrivateObject {
		return netTraceObjectHeader{}, fmt.Errorf("invalid NetTrace object tag: %d", tag[0])
	}
	var typeTags [2]byte
	if _, err := io.ReadFull(reader, typeTags[:]); err != nil {
		return netTraceObjectHeader{}, fmt.Errorf("reading NetTrace type tags: %w", err)
	}
	if typeTags != [2]byte{fastSerializationBeginPrivateObject, fastSerializationNullReference} {
		return netTraceObjectHeader{}, fmt.Errorf("invalid NetTrace type tags: %v", typeTags)
	}

	var fields struct {
		Version        int32
		MinimumVersion int32
		NameLength     int32
	}
	if err := binary.Read(reader, binary.LittleEndian, &fields); err != nil {
		return netTraceObjectHeader{}, fmt.Errorf("reading NetTrace type fields: %w", err)
	}
	const maximumNameLength = int32(len("Microsoft.DotNet.Runtime.EventPipeFile"))
	if fields.NameLength <= 0 || fields.NameLength > maximumNameLength {
		return netTraceObjectHeader{}, fmt.Errorf("invalid NetTrace type name length: %d", fields.NameLength)
	}
	name := make([]byte, fields.NameLength)
	if _, err := io.ReadFull(reader, name); err != nil {
		return netTraceObjectHeader{}, fmt.Errorf("reading NetTrace type name: %w", err)
	}
	if _, err := io.ReadFull(reader, tag[:]); err != nil {
		return netTraceObjectHeader{}, fmt.Errorf("reading NetTrace type end tag: %w", err)
	}
	if tag[0] != fastSerializationEndObject {
		return netTraceObjectHeader{}, fmt.Errorf("invalid NetTrace type end tag: %d", tag[0])
	}
	return netTraceObjectHeader{
		Name: string(name), Version: fields.Version, MinimumVersion: fields.MinimumVersion,
	}, nil
}
