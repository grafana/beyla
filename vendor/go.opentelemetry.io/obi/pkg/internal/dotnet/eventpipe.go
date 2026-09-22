// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
	"unicode/utf16"
)

const (
	ipcCommandSetEventPipe    uint8  = 0x02
	ipcCommandStopTracing     uint8  = 0x01
	ipcCommandCollectTracing2 uint8  = 0x03
	eventPipeBufferSizeMB     uint32 = 16
	eventPipeFormatNetTrace   uint32 = 1
	eventPipeProviderCount    uint32 = 1
	// .NET ProcessorCount keyword; EventCounterIntervalSec enables counter polling.
	systemRuntimeKeywords   uint64 = 0x2
	eventLevelInformational uint32 = 4
)

// encodeEventPipeStart encodes a CollectTracing2 request for System.Runtime EventCounters.
// This is the .NET metrics source.
// https://github.com/dotnet/diagnostics/blob/f09edf7ea9a17a86b236b91eb4c458d0469546b6/documentation/design-docs/ipc-protocol.md#collecttracing2
func encodeEventPipeStart(samplingInterval time.Duration) ([]byte, error) {
	if samplingInterval <= 0 {
		return nil, errors.New("EventPipe sampling interval must be greater than 0")
	}

	payload := binary.LittleEndian.AppendUint32(nil, eventPipeBufferSizeMB)
	payload = binary.LittleEndian.AppendUint32(payload, eventPipeFormatNetTrace)
	payload = append(payload, 0) // requestRundown is false for this metrics session.
	payload = binary.LittleEndian.AppendUint32(payload, eventPipeProviderCount)
	payload = binary.LittleEndian.AppendUint64(payload, systemRuntimeKeywords)
	payload = binary.LittleEndian.AppendUint32(payload, eventLevelInformational)

	interval := strconv.FormatFloat(samplingInterval.Seconds(), 'f', -1, 64)
	for _, value := range []string{"System.Runtime", "EventCounterIntervalSec=" + interval} {
		units := utf16.Encode([]rune(value))
		payload = binary.LittleEndian.AppendUint32(payload, uint32(len(units)+1))
		for _, unit := range units {
			payload = binary.LittleEndian.AppendUint16(payload, unit)
		}
		payload = binary.LittleEndian.AppendUint16(payload, 0)
	}
	return encodeIPCMessage(ipcCommandSetEventPipe, ipcCommandCollectTracing2, payload)
}

type eventPipeSession struct {
	id         uint64
	socketPath string
	stream     net.Conn
}

// startEventPipe starts a .NET System.Runtime EventCounter session and retains its stream.
// The context bounds setup; after success, the caller owns the session's lifetime.
func startEventPipe(ctx context.Context, socketPath string, samplingInterval time.Duration) (*eventPipeSession, error) {
	request, err := encodeEventPipeStart(samplingInterval)
	if err != nil {
		return nil, err
	}
	// Diagnostic IPC allows one command per connection. CollectTracing2 needs
	// a new connection after ProcessInfo2 and retains it for the event stream.
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting for EventPipe session: %w", err)
	}

	keepStream := false
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		stop()
		if !keepStream {
			_ = conn.Close()
		}
	}()
	_, err = io.Copy(conn, bytes.NewReader(request))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("sending EventPipe start request: %w", err)
	}

	payload, err := readIPCResponse(conn)
	// The setup deadline must not close an established metrics stream.
	stop()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("reading EventPipe start response: %w", err)
	}
	if len(payload) != binary.Size(uint64(0)) {
		return nil, fmt.Errorf("invalid EventPipe session ID payload size: %d", len(payload))
	}

	keepStream = true
	return &eventPipeSession{
		id:         binary.LittleEndian.Uint64(payload),
		socketPath: socketPath,
		stream:     conn,
	}, nil
}

// stopEventPipe sends StopTracing on a separate connection and checks the session ID.
// The caller must keep reading the original stream while stopping, then drain it
// to EOF before closing it so the final events are preserved.
func stopEventPipe(ctx context.Context, session *eventPipeSession) error {
	payload := binary.LittleEndian.AppendUint64(nil, session.id)
	request, err := encodeIPCMessage(ipcCommandSetEventPipe, ipcCommandStopTracing, payload)
	if err != nil {
		return err
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", session.socketPath)
	if err != nil {
		return fmt.Errorf("connecting to stop EventPipe session: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_, err = io.Copy(conn, bytes.NewReader(request))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("sending EventPipe stop request: %w", err)
	}
	payload, err = readIPCResponse(conn)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if err != nil {
		return fmt.Errorf("reading EventPipe stop response: %w", err)
	}
	if len(payload) != binary.Size(session.id) {
		return fmt.Errorf("invalid EventPipe stop payload size: %d", len(payload))
	}
	if id := binary.LittleEndian.Uint64(payload); id != session.id {
		return fmt.Errorf("EventPipe stop returned session ID %#x, expected %#x", id, session.id)
	}
	return nil
}
