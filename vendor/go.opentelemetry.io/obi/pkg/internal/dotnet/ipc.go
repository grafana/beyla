// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const ipcMagic = "DOTNET_IPC_V1\x00"

const ipcHRESULTUnknownCommand = 0x80131385

var errIPCUnknownCommand = errors.New("unknown diagnostic IPC command")

const (
	ipcCommandSetServer uint8 = 0xff
	ipcResponseOK       uint8 = 0x00
	ipcResponseError    uint8 = 0xff
)

// ipcHeader is the 20-byte diagnostic IPC wire header.
// Size includes both the header and payload.
// https://github.com/dotnet/diagnostics/blob/f09edf7ea9a17a86b236b91eb4c458d0469546b6/documentation/design-docs/ipc-protocol.md#headers
type ipcHeader struct {
	Magic      [14]byte
	Size       uint16
	CommandSet uint8
	CommandID  uint8
	Reserved   uint16
}

func readIPCHeader(reader io.Reader) (ipcHeader, error) {
	var header ipcHeader
	if err := binary.Read(reader, binary.LittleEndian, &header); err != nil {
		return ipcHeader{}, err
	}
	if string(header.Magic[:]) != ipcMagic {
		return ipcHeader{}, errors.New("invalid diagnostic IPC magic")
	}
	if int(header.Size) < binary.Size(header) {
		return ipcHeader{}, fmt.Errorf("diagnostic IPC message size %d is smaller than its header", header.Size)
	}
	if header.Reserved != 0 {
		return ipcHeader{}, fmt.Errorf("diagnostic IPC reserved field is nonzero: %#x", header.Reserved)
	}

	return header, nil
}

type ipcMessage struct {
	Header  ipcHeader
	Payload []byte
}

func encodeIPCMessage(commandSet, commandID uint8, payload []byte) ([]byte, error) {
	header := ipcHeader{CommandSet: commandSet, CommandID: commandID}
	headerSize := binary.Size(header)
	if len(payload) > math.MaxUint16-headerSize {
		return nil, fmt.Errorf("diagnostic IPC payload size %d exceeds the message size limit", len(payload))
	}

	copy(header.Magic[:], ipcMagic)
	header.Size = uint16(headerSize + len(payload))
	message := make([]byte, int(header.Size))
	if _, err := binary.Encode(message, binary.LittleEndian, header); err != nil {
		return nil, fmt.Errorf("encoding diagnostic IPC header: %w", err)
	}
	copy(message[headerSize:], payload)
	return message, nil
}

func readIPCMessage(reader io.Reader) (ipcMessage, error) {
	header, err := readIPCHeader(reader)
	if err != nil {
		return ipcMessage{}, err
	}

	// The validated uint16 size bounds the allocation. Read only this message;
	// an EventPipe response can be followed immediately by the NetTrace stream.
	payload := make([]byte, int(header.Size)-binary.Size(header))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return ipcMessage{}, fmt.Errorf("reading diagnostic IPC payload: %w", err)
	}
	return ipcMessage{Header: header, Payload: payload}, nil
}

// readIPCResponse returns a successful server response payload or its HRESULT error.
func readIPCResponse(reader io.Reader) ([]byte, error) {
	message, err := readIPCMessage(reader)
	if err != nil {
		return nil, err
	}
	if message.Header.CommandSet != ipcCommandSetServer {
		return nil, fmt.Errorf("unexpected diagnostic IPC response command set: %#x", message.Header.CommandSet)
	}

	switch message.Header.CommandID {
	case ipcResponseOK:
		return message.Payload, nil
	case ipcResponseError:
		if len(message.Payload) != binary.Size(uint32(0)) {
			return nil, fmt.Errorf("invalid diagnostic IPC error payload size: %d", len(message.Payload))
		}
		code := binary.LittleEndian.Uint32(message.Payload)
		if code == ipcHRESULTUnknownCommand {
			return nil, fmt.Errorf("diagnostic IPC server error: HRESULT 0x%08x: %w", code, errIPCUnknownCommand)
		}
		return nil, fmt.Errorf("diagnostic IPC server error: HRESULT 0x%08x", code)
	default:
		return nil, fmt.Errorf("unexpected diagnostic IPC response command: %#x", message.Header.CommandID)
	}
}
