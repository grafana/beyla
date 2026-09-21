// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
)

const (
	ipcCommandSetProcess   uint8 = 0x04
	ipcCommandProcessInfo2 uint8 = 0x04
)

// queryProcessInfo2 queries a runtime's diagnostic socket for its process identity.
// The caller bounds the operation with a context deadline.
func queryProcessInfo2(ctx context.Context, socketPath string) (processInfo, error) {
	request, err := encodeIPCMessage(ipcCommandSetProcess, ipcCommandProcessInfo2, nil)
	if err != nil {
		return processInfo{}, err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return processInfo{}, fmt.Errorf("connecting to diagnostic socket: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	_, err = io.Copy(conn, bytes.NewReader(request))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return processInfo{}, ctxErr
	}
	if err != nil {
		return processInfo{}, fmt.Errorf("sending ProcessInfo2 request: %w", err)
	}

	payload, err := readIPCResponse(conn)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return processInfo{}, ctxErr
	}
	if err != nil {
		return processInfo{}, fmt.Errorf("reading ProcessInfo2 response: %w", err)
	}
	return decodeProcessInfo2(payload)
}
