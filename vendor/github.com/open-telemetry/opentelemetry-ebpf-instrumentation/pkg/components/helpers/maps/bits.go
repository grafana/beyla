package maps

// Bits wraps an unsigned integer that can be used as a bit map
type Bits uint

type builderOpts[T any] struct {
	transform []func(T) T
}

// BuilderOpt allows defining option for building Bits map in the MappedBits method
type BuilderOpt[T any] func(*builderOpts[T])

// WithTransform will apply the provided transformer function to the passed key values
// in the MappedBits constructor function
func WithTransform[T any](transformFunc func(T) T) BuilderOpt[T] {
	return func(o *builderOpts[T]) {
		o.transform = append(o.transform, transformFunc)
	}
}

// MappedBits builds a Bits map from a set of values (e.g. strings) that are mapped in the form
// value --> corresponding Bits value
// in the "maps" constructor argument
func MappedBits[T comparable](values []T, maps map[T]Bits, opts ...BuilderOpt[T]) Bits {
	bo := builderOpts[T]{}
	for _, opt := range opts {
		opt(&bo)
	}

	b := Bits(0)
	for _, value := range values {
		for _, t := range bo.transform {
			value = t(value)
		}
		if val, ok := maps[value]; ok {
			b |= val
		}
	}
	return b
}

// Has returns true if the map contains all the value Bits passed as argument
func (i Bits) Has(value Bits) bool {
	return i&value == value
}
