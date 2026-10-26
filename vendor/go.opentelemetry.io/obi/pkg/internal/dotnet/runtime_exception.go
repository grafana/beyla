// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	maximumExceptionTypes     = 128
	maximumExceptionTypeBytes = 1024
	exceptionTypeOther        = "_OTHER"
)

// exceptionTypes retains admitted names for one process incarnation, across sessions.
type exceptionTypes struct {
	// Values hold canonical copies independent of the event payload strings.
	names map[string]string
}

func (t *exceptionTypes) labelFor(name string) (string, error) {
	if name == "" {
		return "", errors.New("exception type has an empty name")
	}
	if len(name) > maximumExceptionTypeBytes || name == exceptionTypeOther {
		return exceptionTypeOther, nil
	}
	if admitted, ok := t.names[name]; ok {
		return admitted, nil
	}
	if len(t.names) >= maximumExceptionTypes {
		return exceptionTypeOther, nil
	}
	if t.names == nil {
		t.names = make(map[string]string)
	}
	name = strings.Clone(name)
	t.names[name] = name
	return name, nil
}

func decodeExceptionMetric(eventName string, values map[string]any, sessionID string) (netTraceRuntimeEvent, error) {
	if eventName == "MultipleSessionsNotSupportedError" {
		owner, ok := values["runningSessionId"].(string)
		if !ok {
			return netTraceRuntimeEvent{}, errors.New("missing Meter session owner")
		}
		if owner != sessionID {
			return netTraceRuntimeEvent{
				exceptionsUnavailable: true,
				exceptionWarning:      "another diagnostics client owns the Meter subscription",
			}, nil
		}
		return netTraceRuntimeEvent{}, nil
	}
	if values["sessionId"] != sessionID {
		return netTraceRuntimeEvent{}, nil
	}
	switch eventName {
	case "TimeSeriesLimitReached":
		return netTraceRuntimeEvent{exceptionWarning: "runtime exception time-series limit reached; additional types are omitted"}, nil
	case "Error":
		return netTraceRuntimeEvent{
			exceptionsUnavailable: true,
			exceptionWarning:      "runtime Meter collection failed",
		}, nil
	}
	if values["meterName"] != "System.Runtime" || values["instrumentName"] != "dotnet.exceptions" {
		return netTraceRuntimeEvent{}, nil
	}
	tags, ok := values["tags"].(string)
	name, valid := strings.CutPrefix(tags, "error.type=")
	if !ok || !valid || name == "" {
		return netTraceRuntimeEvent{}, errors.New("exception metric has no error.type")
	}
	// The runtime sends interval deltas in rate; value is session-relative.
	rate, ok := values["rate"].(string)
	if !ok {
		return netTraceRuntimeEvent{}, errors.New("exception metric has no delta")
	}
	if rate == "" {
		return netTraceRuntimeEvent{}, nil
	}
	count, err := strconv.ParseFloat(rate, 64)
	if err != nil || math.IsNaN(count) || math.IsInf(count, 0) || count < 0 || count >= math.Exp2(63) || math.Trunc(count) != count {
		return netTraceRuntimeEvent{}, fmt.Errorf("invalid exception metric delta: %q", rate)
	}
	return netTraceRuntimeEvent{exceptionType: name, exceptionCount: uint64(count)}, nil
}

func isCLRExceptionThrown(header netTraceMetadataHeader) bool {
	const exceptionThrownEventID = 80
	const exceptionThrownVersion = 1
	return header.ProviderName == "Microsoft-Windows-DotNETRuntime" &&
		header.EventID == exceptionThrownEventID && header.Version == exceptionThrownVersion
}

// decodeCLRExceptionType reads the fixed ExceptionThrown_V1 manifest layout.
// Native CLR events carry no field definitions in their NetTrace metadata.
func decodeCLRExceptionType(reader *bytes.Reader, pointerSize int32) (string, error) {
	if pointerSize != 4 && pointerSize != 8 {
		return "", fmt.Errorf("invalid CLR pointer size: %d", pointerSize)
	}
	typeName, err := readNetTraceString(reader)
	if err != nil {
		return "", err
	}
	if typeName == "" {
		return "", errors.New("CLR exception event has no valid ExceptionType")
	}
	// Skip the UTF-16 message without allocating or retaining its contents.
	for {
		var unit uint16
		if err := binary.Read(reader, binary.LittleEndian, &unit); err != nil {
			return "", fmt.Errorf("reading CLR exception message: %w", err)
		}
		if unit == 0 {
			break
		}
	}
	// Remaining fields: EIP (pointer), HRESULT (u32), flags and CLR instance ID (u16).
	if reader.Len() != int(pointerSize)+4+2+2 {
		return "", errors.New("invalid CLR exception payload length")
	}
	return typeName, nil
}

// shortCLRExceptionType matches Type.Name for ordinary C# exception names.
// CLR names append generic arguments but preserve the metadata name's arity.
func shortCLRExceptionType(typeName string) string {
	name, _, _ := strings.Cut(typeName, "[")
	if dot := strings.LastIndexAny(name, ".+"); dot >= 0 {
		name = name[dot+1:]
	}
	return name
}
