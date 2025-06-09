// Package ringbuf provides some type aliases to prevent testing/compilation
// errors in non-linux environments due to the use of Cilium's ringbuf package,
// which is only available on Linux.
package ringbuf

import (
	"github.com/cilium/ebpf/ringbuf"
)

type (
	Record = ringbuf.Record
	Reader = ringbuf.Reader
)

var (
	ErrClosed = ringbuf.ErrClosed
	NewReader = ringbuf.NewReader
)
