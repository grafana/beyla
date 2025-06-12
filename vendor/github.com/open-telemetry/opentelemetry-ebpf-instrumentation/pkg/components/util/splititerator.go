package util

import (
	"strings"
)

// alternative to strings.Split(str, delim) - each call to Nex() returns a
// a substring slice, allowing string tokens or lines to be processed in place
// (zero-copy), without the need of allocations
type SplitIterator struct {
	startBuf string
	buf      string
	delim    string
}

func NewSplitIterator(buf string, delim string) *SplitIterator {
	return &SplitIterator{
		startBuf: buf,
		buf:      buf,
		delim:    delim,
	}
}

// Next returns a token and false if there are any tokens available, otherwise
// returns "" and true to convey EOF has been reached
func (sp *SplitIterator) Next() (string, bool) {
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

func (sp *SplitIterator) Reset() {
	sp.buf = sp.startBuf
}
