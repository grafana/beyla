// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ringbuf // import "go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"

import (
	"errors"
	"os"
	"time"
)

type Record struct {
	RawSample []byte
}

var (
	ErrClosed  = os.ErrClosed
	ErrFlushed = errors.New("flushed")
)

type Reader struct{}

func (*Reader) SetDeadline(time.Time)  {}
func (*Reader) ReadInto(*Record) error { return nil }
func (*Reader) Close() error           { return nil }
func (*Reader) Read() (Record, error)  { return Record{}, nil }
func (*Reader) AvailableBytes() int    { return 0 }
func (*Reader) Flush() error           { return nil }

func NewReader(_ any) (*Reader, error) {
	return nil, nil
}
