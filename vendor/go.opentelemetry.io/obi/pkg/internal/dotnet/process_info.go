// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf16"
)

type processInfo struct {
	PID                uint64
	RuntimeCookie      [16]byte
	CommandLine        string
	OperatingSystem    string
	Architecture       string
	EntrypointAssembly string
	CLRVersion         string
}

// decodeProcessInfo2 decodes the response payload of the ProcessInfo2 diagnostic
// IPC command: the namespace PID, runtime cookie, then five strings.
// https://github.com/dotnet/diagnostics/blob/f09edf7ea9a17a86b236b91eb4c458d0469546b6/src/Microsoft.Diagnostics.NETCore.Client/DiagnosticsIpc/ProcessInfo.cs
func decodeProcessInfo2(payload []byte) (processInfo, error) {
	reader := bytes.NewReader(payload)
	var info processInfo
	if err := binary.Read(reader, binary.LittleEndian, &info.PID); err != nil {
		return processInfo{}, fmt.Errorf("reading diagnostic process ID: %w", err)
	}
	if _, err := io.ReadFull(reader, info.RuntimeCookie[:]); err != nil {
		return processInfo{}, fmt.Errorf("reading diagnostic runtime cookie: %w", err)
	}

	for _, field := range []struct {
		name  string
		value *string
	}{
		{"command line", &info.CommandLine},
		{"operating system", &info.OperatingSystem},
		{"architecture", &info.Architecture},
		{"entrypoint assembly", &info.EntrypointAssembly},
		{"CLR version", &info.CLRVersion},
	} {
		value, err := readIPCString(reader)
		if err != nil {
			return processInfo{}, fmt.Errorf("reading diagnostic %s: %w", field.name, err)
		}
		*field.value = value
	}
	if reader.Len() != 0 {
		return processInfo{}, fmt.Errorf("unexpected trailing bytes in ProcessInfo2 payload: %d", reader.Len())
	}
	return info, nil
}

func readIPCString(reader *bytes.Reader) (string, error) {
	var length uint32
	if err := binary.Read(reader, binary.LittleEndian, &length); err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}

	// Length counts UTF-16 code units, including the final null. Check the
	// available bytes before allocation or multiplication of an untrusted length.
	if uint64(length) > uint64(reader.Len()/binary.Size(uint16(0))) {
		return "", io.ErrUnexpectedEOF
	}
	units := make([]uint16, int(length))
	if err := binary.Read(reader, binary.LittleEndian, units); err != nil {
		return "", err
	}
	if units[len(units)-1] != 0 {
		return "", errors.New("diagnostic IPC string is not null terminated")
	}
	units = units[:len(units)-1]
	for i := 0; i < len(units); i++ {
		if utf16.IsSurrogate(rune(units[i])) {
			if i+1 == len(units) || utf16.DecodeRune(rune(units[i]), rune(units[i+1])) == unicode.ReplacementChar {
				return "", errors.New("diagnostic IPC string contains an unpaired UTF-16 surrogate")
			}
			i++
		}
	}
	return string(utf16.Decode(units)), nil
}
