package maps

// MultiCounter maps a counter to a given key
type MultiCounter[K comparable] map[K]*int

// Inc increments the counter associated to the given key and returns the new count.
func (m MultiCounter[K]) Inc(key K) int {
	n, ok := m[key]
	if !ok {
		z := 1
		m[key] = &z
		return 1
	}
	*n++
	return *n
}

// Dec decrements the counter associated to the given key and returns the new count.
func (m MultiCounter[K]) Dec(key K) int {
	n, ok := m[key]
	if !ok {
		z := -1
		m[key] = &z
		return -1
	}
	*n--
	if *n == 0 {
		delete(m, key)
	}
	return *n
}

// Map2 implements a 2-level map where each 1st-level key maps to a 2nd level map.
type Map2[K1, K2 comparable, V any] map[K1]map[K2]V

func (m Map2[K1, K2, V]) Put(key1 K1, key2 K2, val V) {
	m2, ok := m[key1]
	if !ok {
		m2 = map[K2]V{}
		m[key1] = m2
	}
	m2[key2] = val
}

func (m Map2[K1, K2, V]) Get(key1 K1, key2 K2) (V, bool) {
	m2, ok := m[key1]
	if !ok {
		var zero V
		return zero, false
	}
	v, ok := m2[key2]
	return v, ok
}

func (m Map2[K1, K2, V]) Delete(key1 K1, key2 K2) {
	if m2, ok := m[key1]; ok {
		delete(m2, key2)
		if len(m2) == 0 {
			delete(m, key1)
		}
	}
}

// DeleteAll the 2nd-level entries associated with the 1st-level key.
func (m Map2[K1, K2, V]) DeleteAll(key1 K1) {
	delete(m, key1)
}

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
