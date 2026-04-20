// Copyright (c) 2025, Peter Ohler, All rights reserved.

package jp

type norm byte

// Append a fragment string representation of the fragment to the buffer
// then returning the expanded buffer.
func (f norm) Append(buf []byte, bracket, first bool) []byte {
	return buf
}

func (f norm) locate(pp Expr, data any, rest Expr, max int) (locs []Expr) {
	if 0 < len(rest) {
		locs = rest[0].locate(pp, data, rest[1:], max)
	}
	return
}

// Walk continues with the next in rest.
func (f norm) Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any)) {
	if 0 < len(rest) {
		rest[0].Walk(rest[1:], path, nodes, cb)
	}
}

func normalExpr(x Expr) Expr {
	if x.Normal() && 0 < len(x) {
		if _, ok := x[0].(norm); !ok {
			x = append(Expr{norm('n')}, x...)
		}
	}
	return x
}
