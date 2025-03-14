//go:build !linux

package ringbuf

import (
	"io"
	"os"
)

type Record struct {
	RawSample []byte
}

var ErrClosed = os.ErrClosed

func NewReader(_ any) (interface {
	io.Closer
	Read() (Record, error)
}, error) {
	return nil, nil
}
