package export

import "go.opentelemetry.io/otel/attribute"

// AttributesFilter controls which attributes are added
// to a metric
type AttributesFilter struct {
	newSet func() Attributes
}

// Attributes set. Each metric must create its own instance
// by means of AttributesFilter.New()
type Attributes interface {
	PutString(key, value string)
	Slice() []attribute.KeyValue
}

// NewAttributesFilter creates an AttributesFilter that would filter
// the attributes not contained in the allowed list.
// If the allowed list is empty, it won't filter any attribute.
func NewAttributesFilter(allowed []string) AttributesFilter {
	if len(allowed) == 0 {
		return AttributesFilter{newSet: newUnfilteredSet}
	}
	return AttributesFilter{newSet: newFilteredSet(allowed)}
}

func (a *AttributesFilter) New() Attributes {
	return a.newSet()
}

func newFilteredSet(allowed []string) func() Attributes {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		allowedSet[n] = struct{}{}
	}
	return func() Attributes {
		return &filteredSet{
			allowed: allowedSet,
			list:    make([]attribute.KeyValue, 0, len(allowed)),
		}
	}
}

type filteredSet struct {
	allowed map[string]struct{}
	list    []attribute.KeyValue
}

func (f *filteredSet) PutString(key, value string) {
	if _, ok := f.allowed[key]; ok {
		f.list = append(f.list, attribute.String(key, value))
	}
}

func (f *filteredSet) Slice() []attribute.KeyValue {
	return f.list
}

func newUnfilteredSet() Attributes {
	return &unfilteredSet{}
}

type unfilteredSet struct {
	list []attribute.KeyValue
}

func (u *unfilteredSet) PutString(key, value string) {
	u.list = append(u.list, attribute.String(key, value))
}

func (u *unfilteredSet) Slice() []attribute.KeyValue {
	return u.list
}
