package export

import "go.opentelemetry.io/otel/attribute"

// AttributesFilter controls which attributes are added
// to a metric
type AttributesFilter struct {
	allowed map[string]struct{}
}

// Attributes filtered set. Each metric instance must create its own instance
// by means of AttributesFilter.New()
type Attributes struct {
	allowed map[string]struct{}
	list    []attribute.KeyValue
}

// NewAttributesFilter creates an AttributesFilter that would filter
// the attributes not contained in the allowed list.
// If the allowed list is empty, it won't filter any attribute.
func NewAttributesFilter(allowed []string) AttributesFilter {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, n := range allowed {
		allowedSet[n] = struct{}{}
	}
	return AttributesFilter{allowed: allowedSet}
}

func (af *AttributesFilter) New() Attributes {
	return Attributes{
		allowed: af.allowed,
		list:    make([]attribute.KeyValue, 0, len(af.allowed)),
	}
}

func (a *Attributes) PutString(key, value string) {
	if _, ok := a.allowed[key]; ok {
		a.list = append(a.list, attribute.String(key, value))
	}
}

func (a *Attributes) Slice() []attribute.KeyValue {
	return a.list
}
