//go:build !linux

package ringbuf

import (
	"os"
	"time"
)

type Record struct {
	RawSample []byte
}

var ErrClosed = os.ErrClosed

type Reader struct{}

func (*Reader) SetDeadline(time.Time)  {}
func (*Reader) ReadInto(*Record) error { return nil }
func (*Reader) Close() error           { return nil }
func (*Reader) Read() (Record, error)  { return Record{}, nil }

func NewReader(_ any) (*Reader, error) {
	return nil, nil
}
