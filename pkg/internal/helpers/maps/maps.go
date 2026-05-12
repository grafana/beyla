// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package maps

// SetToSlice returns a slice containing the keys of the provided Set/map
func SetToSlice[V comparable](m map[V]struct{}) []V {
	out := make([]V, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// SliceToSet returns a Set/map whose keys are formed by the values in the
// slice argument.
// It will deduplicate any repeated value in the slice
func SliceToSet[V comparable](s []V) map[V]struct{} {
	out := make(map[V]struct{}, len(s))
	for i := range s {
		out[s[i]] = struct{}{}
	}
	return out
}
