// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package ringbuf provides some type aliases to prevent testing/compilation
// errors in non-linux environments due to the use of Cilium's ringbuf package,
// which is only available on Linux.
package ringbuf // import "go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"

import (
	"github.com/cilium/ebpf/ringbuf"
)

type (
	Record = ringbuf.Record
	Reader = ringbuf.Reader
)

var (
	ErrClosed  = ringbuf.ErrClosed
	ErrFlushed = ringbuf.ErrFlushed
	NewReader  = ringbuf.NewReader
)
