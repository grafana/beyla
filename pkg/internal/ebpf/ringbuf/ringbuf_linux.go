// Package ringbuf provides some type aliases to prevent testing/compilation
// errors in non-linux environments due to the use of Cilium's ringbuf package,
// which is only available on Linux.
package ringbuf

import (
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/ringbuf"
)

type Record = ringbuf.Record

var ErrClosed = ringbuf.ErrClose
var ErrClosed = ringbuf.ErrClosed
var NewReader = ringbuf.NewReader
