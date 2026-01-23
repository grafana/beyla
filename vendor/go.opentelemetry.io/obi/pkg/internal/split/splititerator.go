// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package split provides an Iterator that allows for zero-copy string
// splitting.
package split // import "go.opentelemetry.io/obi/pkg/internal/split"

import (
	"strings"
)

// Iterator is alternative to strings.Split(str, delim) - each call to Nex()
// returns a a substring slice, allowing string tokens or lines to be processed
// in place (zero-copy), without the need of allocations
type Iterator struct {
	startBuf string
	buf      string
	delim    string
}

func NewIterator(buf string, delim string) *Iterator {
	return &Iterator{
		startBuf: buf,
		buf:      buf,
		delim:    delim,
	}
}

// Next returns a token and false if there are any tokens available, otherwise
// returns "" and true to convey EOF has been reached
func (sp *Iterator) Next() (string, bool) {
	if len(sp.buf) == 0 {
		return "", true
	}

	index := strings.Index(sp.buf, sp.delim)

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

func (sp *Iterator) Reset() {
	sp.buf = sp.startBuf
}
