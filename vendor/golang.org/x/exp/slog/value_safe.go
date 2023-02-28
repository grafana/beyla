// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build safe_values

package slog

// This file defines the most portable representation of Value.

// A Value can represent any Go value, but unlike type any,
// it can represent most small values without an allocation.
// The zero Value corresponds to nil.
type Value struct {
	// num holds the value for Kinds Int64, Uint64, Float64, Bool and Duration,
	// and nanoseconds since the epoch for KindTime.
	num uint64
	// s holds the value for KindString.
	s string
	// If any is of type Kind, then the value is in num or s as described above.
	// If any is of type *time.Location, then the Kind is Time and time.Time
	// value can be constructed from the Unix nanos in num and the location
	// (monotonic time is not preserved).
	// Otherwise, the Kind is Any and any is the value.
	// (This implies that Values cannot store Kinds or *time.Locations.)
	any any
}

// Kind returns v's Kind.
func (v Value) Kind() Kind {
	switch k := v.any.(type) {
	case Kind:
		return k
	case timeLocation:
		return KindTime
	case []Attr:
		return KindGroup
	case LogValuer:
		return KindLogValuer
	case kind: // a kind is just a wrapper for a Kind
		return KindAny
	default:
		return KindAny
	}
}

func (v Value) str() string {
	return v.s
}

// StringValue returns a new Value for a string.
func StringValue(value string) Value {
	return Value{s: value, any: KindString}
}

// String returns Value's value as a string, formatted like fmt.Sprint. Unlike
// the methods Int64, Float64, and so on, which panic if v is of the
// wrong kind, String never panics.
func (v Value) String() string {
	if v.Kind() == KindString {
		return v.str()
	}
	var buf []byte
	return string(v.append(buf))
}

func groupValue(as []Attr) Value {
	return Value{any: as}
}

func (v Value) group() []Attr {
	return v.any.([]Attr)
}

func (v Value) uncheckedGroup() []Attr { return v.group() }
