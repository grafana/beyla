// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agentctl // import "go.opentelemetry.io/obi/pkg/internal/agentctl"

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

const (
	List byte = iota + 1
	Attach
	Detach
	Claim
	AttachPatch
)

// Patch is the payload of the AttachPatch operation.
type Patch struct {
	Class      string
	Method     string
	Descriptor string
	Value      string
	ExpiresAt  time.Time
}

const patchActionReturn byte = 1

// Exchange implements the private agent protocol used by Java and Node.js.
func Exchange(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, operation byte, method string, cookie uint64) ([]string, error) {
	var request bytes.Buffer
	if operation == Attach {
		writeString(&request, method)
	}
	if operation == Attach || operation == Detach {
		_ = binary.Write(&request, binary.BigEndian, cookie)
	}
	connection, err := send(ctx, pid, port, token, session, operation, request.Bytes())
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := readStatus(connection); err != nil {
		return nil, err
	}
	if operation != List {
		return nil, nil
	}
	return readSymbols(connection)
}

// ExchangePatch sends the AttachPatch operation, which Java agents from before it existed reject.
func ExchangePatch(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, patch Patch, cookie uint64) error {
	var request bytes.Buffer
	writeString(&request, patch.Class)
	writeString(&request, patch.Method)
	writeString(&request, patch.Descriptor)
	request.WriteByte(patchActionReturn)
	writeString(&request, patch.Value)
	_ = binary.Write(&request, binary.BigEndian, patch.ExpiresAt.UnixMilli())
	_ = binary.Write(&request, binary.BigEndian, cookie)
	connection, err := send(ctx, pid, port, token, session, AttachPatch, request.Bytes())
	if err != nil {
		return err
	}
	defer connection.Close()
	return readStatus(connection)
}

// send connects inside the target's network namespace and writes one request. The returned
// connection is closed early if ctx ends, and must be closed by the caller.
func send(ctx context.Context, pid app.PID, port uint32, token, session [16]byte, operation byte, payload []byte) (net.Conn, error) {
	if port == 0 || port > 65535 {
		return nil, errors.New("dynamic agent is not ready")
	}
	var connection net.Conn
	err := netns.WithNetNS(int(pid), func() error {
		var err error
		connection, err = (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
		return err
	})
	if err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		connection.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	var request bytes.Buffer
	request.Write(token[:])
	request.Write(session[:])
	request.WriteByte(operation)
	request.Write(payload)
	if _, err := io.Copy(connection, &request); err != nil {
		stop()
		connection.Close()
		return nil, err
	}
	return &stoppingConn{Conn: connection, stop: stop}, nil
}

type stoppingConn struct {
	net.Conn
	stop func() bool
}

func (c *stoppingConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

func readStatus(connection io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(connection, status[:]); err != nil {
		return err
	}
	if status[0] == 0 {
		return nil
	}
	message, err := ReadString(connection)
	if err != nil {
		return err
	}
	return errors.New(message)
}

func readSymbols(connection io.Reader) ([]string, error) {
	var count uint32
	if err := binary.Read(connection, binary.BigEndian, &count); err != nil {
		return nil, err
	}
	if count > 100000 {
		return nil, fmt.Errorf("agent symbol list exceeds limit: %d", count)
	}
	symbols := make([]string, 0, count)
	size := 0
	for range count {
		symbol, err := ReadString(connection)
		if err != nil {
			return nil, err
		}
		size += len(symbol)
		if size > 64<<20 {
			return nil, errors.New("agent symbol catalog exceeds byte limit")
		}
		symbols = append(symbols, symbol)
	}
	slices.Sort(symbols)
	return symbols, nil
}

func writeString(buffer *bytes.Buffer, value string) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(value)))
	buffer.WriteString(value)
}

func ReadString(reader io.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return "", err
	}
	if size > 65536 {
		return "", errors.New("agent control string exceeds limit")
	}
	text := make([]byte, size)
	_, err := io.ReadFull(reader, text)
	return string(text), err
}
