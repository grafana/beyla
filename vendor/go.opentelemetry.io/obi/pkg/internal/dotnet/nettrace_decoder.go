// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Decoder resource limits bound retained metadata and per-thread sequence state.
const (
	maximumMetadataDefinitions = 1024
	maximumCaptureThreads      = 4096
)

const (
	netTraceSequencePointHeaderSize   = 8 + 4 // timestamp (uint64) and thread count (uint32).
	netTraceSequencePointThreadIDSize = 8
	netTraceSequencePointThreadSize   = netTraceSequencePointThreadIDSize + 4 // capture thread ID (uint64) and sequence (uint32).
)

type netTraceMetadata struct {
	Header netTraceMetadataHeader
	Fields []netTraceField
}

// netTraceRuntimeEvent holds a counter, GC event, exception count, or subscription diagnostic.
// Events share one sequence so collection boundaries retain stream order.
type netTraceRuntimeEvent struct {
	gc                    *gcRuntimeEvent
	counter               runtimeCounter
	exceptionType         string
	exceptionCount        uint64
	exceptionWarning      string
	exceptionsUnavailable bool
}

type netTraceDecoder struct {
	pointerSize      int32
	metricsSessionID string
	metadata         map[uint32]netTraceMetadata
	sequences        map[uint64]uint32
	gcOrder          gcEventOrder
}

// readRuntimeEvents delivers decoded counters, exception counts, and diagnostics in stream order.
// The caller owns the stream and closes it to interrupt a blocked read.
func readRuntimeEvents(stream io.Reader, expectedPID uint64, metricsSessionID string, consume func(netTraceRuntimeEvent) error) error {
	reader := newNetTraceReader(stream)
	info, err := readNetTracePreamble(reader)
	if err != nil {
		return err
	}
	if info.ProcessID <= 0 || uint64(info.ProcessID) != expectedPID {
		return fmt.Errorf("NetTrace process ID %d does not match expected PID %d", info.ProcessID, expectedPID)
	}
	decoder := netTraceDecoder{pointerSize: info.PointerSize, metricsSessionID: metricsSessionID}
	for {
		header, payload, err := readNetTraceBlock(reader)
		if err != nil {
			return err
		}
		if header.EndOfStream {
			ordered, err := decoder.gcOrder.finish()
			if err != nil {
				return err
			}
			for i := range ordered {
				if err := consume(netTraceRuntimeEvent{gc: &ordered[i]}); err != nil {
					return err
				}
			}
			return nil
		}
		if header.Name == "SPBlock" {
			if err := decoder.checkSequencePoint(payload); err != nil {
				return err
			}
			watermark := int64(binary.LittleEndian.Uint64(payload))
			ordered, err := decoder.gcOrder.releaseBefore(watermark)
			if err != nil {
				return err
			}
			for i := range ordered {
				if err := consume(netTraceRuntimeEvent{gc: &ordered[i]}); err != nil {
					return err
				}
			}
			continue
		}
		if header.Name != "EventBlock" && header.Name != "MetadataBlock" {
			continue
		}
		events, err := decoder.decodeEventBlock(header.Name, payload)
		if err != nil {
			return err
		}
		for _, event := range events {
			if err := consume(event); err != nil {
				return err
			}
		}
	}
}

// decodeEventBlock retains metadata definitions and decodes runtime counters
// and CLR or Meter exception events. Calls must follow stream order.
func (d *netTraceDecoder) decodeEventBlock(name string, payload []byte) ([]netTraceRuntimeEvent, error) {
	if name != "MetadataBlock" && name != "EventBlock" {
		return nil, fmt.Errorf("expected NetTrace event or metadata block, got %q", name)
	}
	reader := bytes.NewReader(payload)
	compressed, err := readNetTraceEventBlockHeader(reader)
	if err != nil {
		return nil, err
	}
	if !compressed {
		return nil, errors.New("uncompressed NetTrace event blocks are unsupported")
	}
	var previous netTraceEventHeader
	var events []netTraceRuntimeEvent
	for reader.Len() > 0 {
		event, err := readNetTraceCompressedEventHeader(reader, previous)
		if err != nil {
			return nil, err
		}
		start := len(payload) - reader.Len()
		valuesReader := bytes.NewReader(payload[start : start+int(event.PayloadSize)])
		if _, err := reader.Seek(int64(event.PayloadSize), io.SeekCurrent); err != nil {
			return nil, err
		}
		previous = event
		if name == "MetadataBlock" {
			if event.MetadataID != 0 {
				return nil, errors.New("nonzero metadata ID in NetTrace metadata block")
			}
			definition, err := readNetTraceMetadataHeader(valuesReader)
			if err != nil {
				return nil, err
			}
			if _, exists := d.metadata[definition.MetadataID]; exists {
				return nil, fmt.Errorf("duplicate NetTrace metadata ID: %d", definition.MetadataID)
			}
			if len(d.metadata) >= maximumMetadataDefinitions {
				return nil, errors.New("NetTrace metadata exceeds decoder limit")
			}
			fields, err := readNetTraceMetadataFields(valuesReader)
			if err != nil {
				return nil, err
			}
			if d.metadata == nil {
				d.metadata = make(map[uint32]netTraceMetadata)
			}
			d.metadata[definition.MetadataID] = netTraceMetadata{Header: definition, Fields: fields}
			continue
		}
		definition, exists := d.metadata[event.MetadataID]
		if !exists {
			return nil, fmt.Errorf("unknown NetTrace metadata ID: %d", event.MetadataID)
		}
		if err := d.checkSequence(event.CaptureThreadID, event.SequenceNumber, true); err != nil {
			return nil, err
		}
		// Ignored events can also establish a timestamp watermark for GC events.
		if event.Sorted {
			ordered, err := d.gcOrder.releaseBefore(event.Timestamp)
			if err != nil {
				return nil, err
			}
			for i := range ordered {
				events = append(events, netTraceRuntimeEvent{gc: &ordered[i]})
			}
		}
		gc, err := decodeCLRGCEvent(definition.Header, event, valuesReader, d.pointerSize)
		if err != nil {
			return nil, err
		}
		if gc != nil {
			if err := d.gcOrder.add(*gc); err != nil {
				return nil, err
			}
			continue
		}
		eventName := definition.Header.EventName
		isException := isCLRExceptionThrown(definition.Header)
		isMeter := d.metricsSessionID != "" && definition.Header.ProviderName == "System.Diagnostics.Metrics" &&
			(eventName == "CounterRateValuePublished" || eventName == "TimeSeriesLimitReached" || eventName == "Error" || eventName == "MultipleSessionsNotSupportedError")
		isCounter := definition.Header.ProviderName == "System.Runtime" &&
			(eventName == "EventCounters" || eventName == "ProcessorCount")
		if !isException && !isMeter && !isCounter {
			continue
		}
		if isException {
			typeName, err := decodeCLRExceptionType(valuesReader, d.pointerSize)
			if err != nil {
				return nil, err
			}
			typeName = shortCLRExceptionType(typeName)
			if typeName == "" {
				return nil, errors.New("CLR exception type normalizes to an empty name")
			}
			events = append(events, netTraceRuntimeEvent{exceptionType: typeName, exceptionCount: 1})
			continue
		}
		values, err := readNetTraceValues(valuesReader, definition.Fields)
		if err != nil {
			return nil, err
		}
		if valuesReader.Len() != 0 {
			return nil, errors.New("trailing bytes in NetTrace event payload")
		}
		if isMeter {
			update, err := decodeExceptionMetric(eventName, values, d.metricsSessionID)
			if err != nil {
				return nil, err
			}
			if update.exceptionType != "" || update.exceptionWarning != "" {
				events = append(events, update)
			}
			continue
		}
		var counter runtimeCounter
		if eventName == "ProcessorCount" {
			counter, err = decodeProcessorCount(values)
		} else {
			counter, err = decodeRuntimeCounter(values)
		}
		if err != nil {
			return nil, err
		}
		if counter.Name == "" {
			continue
		}
		events = append(events, netTraceRuntimeEvent{counter: counter})
	}
	return events, nil
}

// checkSequence rejects dropped events before their counter deltas are used.
// Sequence numbers are per capture thread and wrap as unsigned 32-bit values.
func (d *netTraceDecoder) checkSequence(thread uint64, sequence uint32, event bool) error {
	if previous, exists := d.sequences[thread]; exists {
		expected := previous
		if event {
			expected++
		}
		if sequence != expected {
			return fmt.Errorf("NetTrace event loss or thread reset: thread %d sequence %d, expected %d", thread, sequence, expected)
		}
	}
	if d.sequences == nil {
		d.sequences = make(map[uint64]uint32)
	}
	if _, exists := d.sequences[thread]; !exists && len(d.sequences) >= maximumCaptureThreads {
		return errors.New("NetTrace capture threads exceed decoder limit")
	}
	d.sequences[thread] = sequence
	return nil
}

// checkSequencePoint validates the .NET sequence checkpoint, including losses
// after the last event seen for a thread.
func (d *netTraceDecoder) checkSequencePoint(payload []byte) error {
	if len(payload) < netTraceSequencePointHeaderSize {
		return errors.New("truncated NetTrace sequence point")
	}
	count := binary.LittleEndian.Uint32(payload[8:])
	if uint64(count)*netTraceSequencePointThreadSize != uint64(len(payload)-netTraceSequencePointHeaderSize) {
		return errors.New("invalid NetTrace sequence point thread count")
	}
	for offset := netTraceSequencePointHeaderSize; offset < len(payload); offset += netTraceSequencePointThreadSize {
		thread := binary.LittleEndian.Uint64(payload[offset:])
		sequence := binary.LittleEndian.Uint32(payload[offset+netTraceSequencePointThreadIDSize:])
		if err := d.checkSequence(thread, sequence, false); err != nil {
			return err
		}
	}
	return nil
}
