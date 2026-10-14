// Copyright (c) 2020, Peter Ohler, All rights reserved.

package jp

// Frag represents a JSONPath fragment. A JSONPath expression is composed of
// fragments (Frag) linked together to form a full path expression.
type Frag interface {

	// Append a fragment string representation of the fragment to the buffer
	// then returning the expanded buffer.
	Append(buf []byte, bracket, first bool) []byte

	locate(pp Expr, data any, rest Expr, max int) (locs []Expr)

	// Walk the matching elements in tail of nodes and call cb on the matches
	// or follow on to the matching if not the last fragment in an
	// expression. The rest argument is the rest of the expression after this
	// fragment. The path is the normalized path up to this point. The nodes
	// argument is the chain of data elements to the current location.
	Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any))
}
