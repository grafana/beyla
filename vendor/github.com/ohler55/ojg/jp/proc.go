// Copyright (c) 2024, Peter Ohler, All rights reserved.

package jp

import (
	"fmt"
)

// CompileScript if non-nil should return object that implments the Procedure
// interface. This function is called when a script notation bracketed by [(
// and )] is encountered. Note the string code argument will included the open
// and close parenthesis but not the square brackets.
var CompileScript func(code []byte) Procedure

// Proc is a script used as a procedure which is a script not limited to being
// a selector. While both Locate() and Walk() are supported the results may
// not be as expected since the procedure can modify the original
// data. Remove() is not supported with this fragment type.
type Proc struct {
	Procedure Procedure
	Script    []byte
}

// MustNewProc creates a new Proc and panics on error.
func MustNewProc(code []byte) (p *Proc) {
	if CompileScript == nil {
		panic(fmt.Errorf("jp.CompileScript has not been set"))
	}
	return &Proc{
		Procedure: CompileScript(code),
		Script:    code,
	}
}

// String representation of the proc.
func (p *Proc) String() string {
	return string(p.Append([]byte{}, true, false))
}

// Append a fragment string representation of the fragment to the buffer
// then returning the expanded buffer.
func (p *Proc) Append(buf []byte, _, _ bool) []byte {
	buf = append(buf, "["...)
	buf = append(buf, p.Script...)

	return append(buf, ']')
}

func (p *Proc) locate(pp Expr, data any, rest Expr, max int) (locs []Expr) {
	got := p.Procedure.Get(data)
	if len(rest) == 0 { // last one
		for i := range got {
			locs = locateAppendFrag(locs, pp, Nth(i))
			if 0 < max && max <= len(locs) {
				break
			}
		}
	} else {
		cp := append(pp, nil) // place holder
		for i, v := range got {
			cp[len(pp)] = Nth(i)
			locs = locateContinueFrag(locs, cp, v, rest, max)
			if 0 < max && max <= len(locs) {
				break
			}
		}
	}
	return
}

// Walk each element returned from the procedure call. Note that this may or
// may not correspond to the original data as the procedure can modify not only
// the elements in the original data but also the contents of each.
func (p *Proc) Walk(rest, path Expr, nodes []any, cb func(path Expr, nodes []any)) {
	path = append(path, nil)
	data := nodes[len(nodes)-1]
	nodes = append(nodes, nil)

	for i, v := range p.Procedure.Get(data) {
		path[len(path)-1] = Nth(i)
		nodes[len(nodes)-1] = v
		if 0 < len(rest) {
			rest[0].Walk(rest[1:], path, nodes, cb)
		} else {
			cb(path, nodes)
		}
	}
}
