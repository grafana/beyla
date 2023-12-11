package helpers

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
