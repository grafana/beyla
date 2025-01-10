//go:build linux

package tcmanager

func removeIf[T any](s []T, pred func(T) bool) []T {
	i := 0

	for _, v := range s {
		if !pred(v) {
			s[i] = v
			i++
		}
	}

	return s[:i]
}

func apply[T any](s []T, applyFunc func(T)) {
	for _, v := range s {
		applyFunc(v)
	}
}
