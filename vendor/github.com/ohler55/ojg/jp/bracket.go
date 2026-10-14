// Copyright (c) 2020, Peter Ohler, All rights reserved.

package jp

// Bracket is used as a flag to indicate the path should be displayed in a
// bracketed representation.
type Bracket byte

// Append a fragment string representation of the fragment to the buffer
// then returning the expanded buffer.
func (f Bracket) Append(buf []byte, bracket, first bool) []byte {
	return buf
}

func (f Bracket) locate(pp Expr, data any, rest Expr, max int) (locs []Expr) {
	if 0 < len(rest) {
		locs = rest[0].locate(pp, data, rest[1:], max)
	}
	return
}

// Walk continues with the next in rest.
func (f Bracket) Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any)) {
	if 0 < len(rest) {
		rest[0].Walk(rest[1:], path, nodes, cb)
	} else {
		cb(path, nodes)
	}
}
