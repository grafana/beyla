// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const (
	clrGCStartEventID             uint32 = 1
	clrGCEndEventID               uint32 = 2
	clrGCPerHeapHistoryEventID    uint32 = 204
	clrGCGlobalHeapHistoryEventID uint32 = 205
)

type gcRuntimeEvent struct {
	eventID   uint32
	timestamp int64
	threadID  uint64

	collection     gcCollectionEvent
	globalHistory  gcGlobalHeapHistory
	perHeapHistory gcPerHeapHistory
}

type gcCollectionEvent struct {
	count         uint32
	depth         uint32
	clrInstanceID uint16
}

type gcGlobalHeapHistory struct {
	depth         uint32
	heapCount     uint32
	clrInstanceID uint16
}

type gcPerHeapHistory struct {
	heapIndex     uint32
	clrInstanceID uint16
	// Fragmentation entries follow DotnetHeapGenerations.
	fragmentation [runtimemetrics.DotnetHeapGenerationCount]uint64
}

// GCGlobalHeapHistory_V4 has a fixed header followed by Count uint32 timings.
type gcGlobalHeapHistoryHeader struct {
	FinalYoungestDesired uint64
	NumHeaps             int32
	CondemnedGeneration  uint32
	Gen0ReductionCount   uint32
	Reason               uint32
	GlobalMechanisms     uint32
	CLRInstanceID        uint16
	PauseMode            uint32
	MemoryPressure       uint32
	CondemnReasons0      uint32
	CondemnReasons1      uint32
	Count                uint32
}

func clrGCEventVersion(header netTraceMetadataHeader) (uint32, bool) {
	if header.ProviderName != "Microsoft-Windows-DotNETRuntime" {
		return 0, false
	}
	switch header.EventID {
	case clrGCStartEventID:
		return 2, true
	case clrGCEndEventID:
		return 1, true
	case clrGCPerHeapHistoryEventID:
		return 3, true
	case clrGCGlobalHeapHistoryEventID:
		return 4, true
	default:
		return 0, false
	}
}

func decodeCLRGCEvent(definition netTraceMetadataHeader, event netTraceEventHeader, reader *bytes.Reader, pointerSize int32) (*gcRuntimeEvent, error) {
	version, supported := clrGCEventVersion(definition)
	if !supported {
		return nil, nil
	}
	if definition.Version != version {
		return nil, fmt.Errorf("unsupported CLR GC event %d version: %d", definition.EventID, definition.Version)
	}
	decoded := gcRuntimeEvent{
		eventID:   definition.EventID,
		timestamp: event.Timestamp,
		threadID:  event.ThreadID,
	}
	var err error
	switch definition.EventID {
	case clrGCStartEventID:
		decoded.collection, err = decodeCLRGCStart(reader)
	case clrGCEndEventID:
		decoded.collection, err = decodeCLRGCEnd(reader)
	case clrGCPerHeapHistoryEventID:
		decoded.perHeapHistory, err = decodeCLRGCPerHeapHistory(reader, pointerSize)
	case clrGCGlobalHeapHistoryEventID:
		decoded.globalHistory, err = decodeCLRGCGlobalHeapHistory(reader)
	}
	if err != nil {
		return nil, fmt.Errorf("decoding CLR GC event %d: %w", definition.EventID, err)
	}
	return &decoded, nil
}

func decodeCLRGCStart(reader *bytes.Reader) (gcCollectionEvent, error) {
	var payload struct {
		Count                uint32
		Depth                uint32
		Reason               uint32
		Type                 uint32
		CLRInstanceID        uint16
		ClientSequenceNumber uint64
	}
	if reader.Len() != binary.Size(payload) {
		return gcCollectionEvent{}, fmt.Errorf("invalid CLR GC start payload size: %d", reader.Len())
	}
	if err := binary.Read(reader, binary.LittleEndian, &payload); err != nil {
		return gcCollectionEvent{}, fmt.Errorf("reading CLR GC start: %w", err)
	}
	if payload.Depth >= runtimemetrics.DotnetGCGenerationCount {
		return gcCollectionEvent{}, fmt.Errorf("invalid CLR GC start depth: %d", payload.Depth)
	}
	return gcCollectionEvent{
		count:         payload.Count,
		depth:         payload.Depth,
		clrInstanceID: payload.CLRInstanceID,
	}, nil
}

func decodeCLRGCEnd(reader *bytes.Reader) (gcCollectionEvent, error) {
	var payload struct {
		Count         uint32
		Depth         uint32
		CLRInstanceID uint16
	}
	if reader.Len() != binary.Size(payload) {
		return gcCollectionEvent{}, fmt.Errorf("invalid CLR GC end payload size: %d", reader.Len())
	}
	if err := binary.Read(reader, binary.LittleEndian, &payload); err != nil {
		return gcCollectionEvent{}, fmt.Errorf("reading CLR GC end: %w", err)
	}
	if payload.Depth >= runtimemetrics.DotnetGCGenerationCount {
		return gcCollectionEvent{}, fmt.Errorf("invalid CLR GC end depth: %d", payload.Depth)
	}
	return gcCollectionEvent{
		count:         payload.Count,
		depth:         payload.Depth,
		clrInstanceID: payload.CLRInstanceID,
	}, nil
}

func decodeCLRGCGlobalHeapHistory(reader *bytes.Reader) (gcGlobalHeapHistory, error) {
	var header gcGlobalHeapHistoryHeader
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return gcGlobalHeapHistory{}, fmt.Errorf("reading CLR GC global heap history: %w", err)
	}
	if header.NumHeaps <= 0 {
		return gcGlobalHeapHistory{}, fmt.Errorf("invalid CLR GC heap count: %d", header.NumHeaps)
	}
	if header.CondemnedGeneration >= runtimemetrics.DotnetGCGenerationCount {
		return gcGlobalHeapHistory{}, fmt.Errorf("invalid CLR GC history depth: %d", header.CondemnedGeneration)
	}
	if uint64(header.Count)*uint64(binary.Size(uint32(0))) != uint64(reader.Len()) {
		return gcGlobalHeapHistory{}, fmt.Errorf("invalid CLR GC history timing count: %d", header.Count)
	}
	if _, err := reader.Seek(0, io.SeekEnd); err != nil {
		return gcGlobalHeapHistory{}, fmt.Errorf("skipping CLR GC history timings: %w", err)
	}
	return gcGlobalHeapHistory{
		depth:         header.CondemnedGeneration,
		heapCount:     uint32(header.NumHeaps),
		clrInstanceID: header.CLRInstanceID,
	}, nil
}

func decodeCLRGCPerHeapHistory(reader *bytes.Reader, pointerSize int32) (gcPerHeapHistory, error) {
	history, err := readCLRGCPerHeapHeader(reader, pointerSize)
	if err != nil {
		return gcPerHeapHistory{}, err
	}
	for generation := range history.fragmentation {
		value, err := readCLRGCGenerationFragmentation(reader, pointerSize)
		if err != nil {
			return gcPerHeapHistory{}, fmt.Errorf("decoding CLR GC generation %d: %w", generation, err)
		}
		history.fragmentation[generation] = value
	}
	if reader.Len() != 0 {
		return gcPerHeapHistory{}, fmt.Errorf("trailing bytes in CLR GC per-heap history: %d", reader.Len())
	}
	return history, nil
}

// readCLRGCPerHeapHeader reads the heap identity and validates the generation count.
// Seven header fields use the target process's pointer width: 4 bytes for a
// 32-bit process or 8 for a 64-bit process, as reported in the NetTrace header.
func readCLRGCPerHeapHeader(reader *bytes.Reader, pointerSize int32) (gcPerHeapHistory, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return gcPerHeapHistory{}, fmt.Errorf("invalid CLR pointer size: %d", pointerSize)
	}
	const pointerFields, integerFields = 7, 7
	instanceSize := binary.Size(uint16(0))
	integerSize := binary.Size(uint32(0))
	headerSize := instanceSize + pointerFields*int(pointerSize) + integerFields*integerSize
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(reader, header); err != nil {
		return gcPerHeapHistory{}, fmt.Errorf("reading CLR GC per-heap history header: %w", err)
	}
	// The header ends with HeapIndex (uint32), ExtraGen0Commit (pointer), and Count (uint32).
	countOffset := headerSize - integerSize
	heapIndexOffset := countOffset - int(pointerSize) - integerSize
	count := binary.LittleEndian.Uint32(header[countOffset:])
	if count != runtimemetrics.DotnetHeapGenerationCount {
		return gcPerHeapHistory{}, fmt.Errorf("invalid CLR GC history generation count: %d", count)
	}
	return gcPerHeapHistory{
		heapIndex:     binary.LittleEndian.Uint32(header[heapIndexOffset:]),
		clrInstanceID: binary.LittleEndian.Uint16(header),
	}, nil
}

// readCLRGCGenerationFragmentation reads ten fields encoded with the target's
// pointer width. FreeListAfter and FreeObjAfter hold unused bytes after the GC;
// their sum is this heap's contribution to the generation's FragmentationAfterBytes.
func readCLRGCGenerationFragmentation(reader *bytes.Reader, pointerSize int32) (uint64, error) {
	const (
		generationFieldCount = 10
		freeListAfterIndex   = 4
		freeObjectAfterIndex = 5
	)
	var fields [generationFieldCount]uint64
	switch pointerSize {
	case 4:
		var narrow [generationFieldCount]uint32
		if err := binary.Read(reader, binary.LittleEndian, &narrow); err != nil {
			return 0, fmt.Errorf("reading CLR GC generation: %w", err)
		}
		fields[freeListAfterIndex] = uint64(narrow[freeListAfterIndex])
		fields[freeObjectAfterIndex] = uint64(narrow[freeObjectAfterIndex])
	case 8:
		if err := binary.Read(reader, binary.LittleEndian, &fields); err != nil {
			return 0, fmt.Errorf("reading CLR GC generation: %w", err)
		}
	default:
		return 0, fmt.Errorf("invalid CLR pointer size: %d", pointerSize)
	}
	freeList, freeObjects := fields[freeListAfterIndex], fields[freeObjectAfterIndex]
	if freeList > math.MaxInt64 || freeObjects > math.MaxInt64-freeList {
		return 0, errors.New("CLR GC fragmentation exceeds exporter integer range")
	}
	return freeList + freeObjects, nil
}
