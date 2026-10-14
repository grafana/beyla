// Copyright (c) 2025, Peter Ohler, All rights reserved.

package jp

// Procedure defines the interface for functions for script fragments between
// [( and )] delimiters.
type Procedure interface {
	// Get should return a list of matching in the data element.
	Get(data any) []any

	// First should return a single matching in the data element or nil if
	// there are no matches.
	First(data any) any
}
