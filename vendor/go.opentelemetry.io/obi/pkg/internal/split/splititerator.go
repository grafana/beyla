// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package split provides a generic Iterator for zero-copy splitting of
// strings and byte slices.
package split // import "go.opentelemetry.io/obi/pkg/internal/split"

import (
	"bytes"
	"strings"
)

// Iterator is an alternative to strings.Split / bytes.Split — each call to
// Next returns a sub-slice of the original, allowing tokens or lines to be
// processed in place without allocations.
type Iterator[T string | []byte] struct {
	startBuf T
	buf      T
	delim    T
	indexOf  func(T, T) int
}

func NewStringIterator(buf, delim string) Iterator[string] {
	if len(delim) == 0 {
		panic("split: empty delimiter")
	}
	return Iterator[string]{startBuf: buf, buf: buf, delim: delim, indexOf: strings.Index}
}

func NewBytesIterator(buf, delim []byte) Iterator[[]byte] {
	if len(delim) == 0 {
		panic("split: empty delimiter")
	}
	return Iterator[[]byte]{startBuf: buf, buf: buf, delim: delim, indexOf: bytes.Index}
}

// Next returns a token and false if there are any tokens available, otherwise
// returns the zero value and true to convey EOF has been reached.
func (sp *Iterator[T]) Next() (T, bool) {
	if len(sp.buf) == 0 {
		var zero T
		return zero, true
	}

	index := sp.indexOf(sp.buf, sp.delim)

	if index == -1 {
		buf := sp.buf
		sp.buf = sp.buf[len(sp.buf):]
		return buf, false
	}

	index += len(sp.delim)

	buf := sp.buf[:index]
	sp.buf = sp.buf[index:]

	return buf, false
}

// Reset repositions the iterator to the beginning of the buffer.
func (sp *Iterator[T]) Reset() {
	sp.buf = sp.startBuf
}
