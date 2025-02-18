package filter

import (
	"fmt"

	"github.com/gobwas/glob"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
)

// AttributesConfig stores the user-provided section for filtering either Application or Network
// records by attribute values
type AttributesConfig struct {
	Application AttributeFamilyConfig `yaml:"application"`
	Network     AttributeFamilyConfig `yaml:"network"`
}

// AttributeFamilyConfig maps, for a given record, each attribute with its MatchDefinition
type AttributeFamilyConfig map[string]MatchDefinition

// ByAttribute provides a pipeline node that drops all the records of type T (*ebpf.Record, or *request.Span)
// that do not match the provided AttributeFamilyConfig.
func ByAttribute[T any](config AttributeFamilyConfig, getters attributes.NamedGetters[T, string]) pipe.MiddleProvider[[]T, []T] {
	return func() (pipe.MiddleFunc[[]T, []T], error) {
		if len(config) == 0 {
			// No filter configuration provided. The node will be ignored
			// and bypassed by the Pipes library
			return pipe.Bypass[[]T](), nil
		}
		f, err := newFilter(config, getters)
		if err != nil {
			return nil, err
		}
		return f.doFilter, nil
	}
}

type filter[T any] struct {
	matchers []Matcher[T]
}

func newFilter[T any](config AttributeFamilyConfig, getters attributes.NamedGetters[T, string]) (*filter[T], error) {
	// Internally, from code, we use the OTEL-like naming (attr.Name) for the attributes,
	// which usually uses dot-separation but sometimes also use underscore.
	// Since we allow users to specify metrics in both formats, we convert any user-provided
	// attributes to Prometheus-like, which uniquely uses underscores.
	// Then, to validate the user-provided input, we map the prom-like attributes to
	// our internal representation.
	attrProm2Normal := map[string]attr.Name{}
	for normalizedName := range attributes.AllAttributeNames() {
		attrProm2Normal[normalizedName.Prom()] = normalizedName
	}
	// Validate and build Matcher implementations for the user-provided attributes.
	var matchers []Matcher[T]
	for attrStr, match := range config {
		normalAttr, ok := attrProm2Normal[attr.Name(attrStr).Prom()]
		if !ok {
			return nil, fmt.Errorf("attribute filter: unknown attribute name %q", attrStr)
		}
		matcher, err := buildMatcher(getters, normalAttr, &match)
		if err != nil {
			return nil, fmt.Errorf("trying to filter by attribute %s: %w", attrStr, err)
		}
		matchers = append(matchers, matcher)
	}
	return &filter[T]{matchers: matchers}, nil
}

// buildMatcher returns a Matcher given an attribute name, the user-provided MatchDefinition, and the provided
// list of getters for a given record type T.
func buildMatcher[T any](getters attributes.NamedGetters[T, string], attribute attr.Name, def *MatchDefinition) (Matcher[T], error) {
	m := Matcher[T]{}
	if err := def.Validate(); err != nil {
		return m, err
	}
	if def.Match != "" {
		var err error
		if m.Glob, err = glob.Compile(def.Match); err != nil {
			return m, fmt.Errorf("invalid glob in match property: %w", err)
		}
	} else {
		var err error
		if m.Glob, err = glob.Compile(def.NotMatch); err != nil {
			return m, fmt.Errorf("invalid glob in not_match property: %w", err)
		}
		m.Negate = true
	}
	getter, ok := getters(attribute)
	if !ok {
		var t T
		return m, fmt.Errorf("not existing for type %T", t)
	}
	m.Getter = getter
	return m, nil
}

// main pipeline node loop
func (f *filter[T]) doFilter(in <-chan []T, out chan<- []T) {
	for i := range in {
		if i = f.filterBatch(i); len(i) > 0 {
			out <- i
		}
	}
}

// filterBatch removes from the input slice the records that do not match
// the user-provided attribute matchers
func (f *filter[T]) filterBatch(batch []T) []T {
	w := 0
batchLoop:
	for t := range batch {
		for m := range f.matchers {
			if !f.matchers[m].Matches(batch[t]) {
				continue batchLoop
			}
		}
		batch[w] = batch[t]
		w++
	}
	return batch[:w]
}
