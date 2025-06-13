package filter

import (
	"context"
	"fmt"

	"github.com/gobwas/glob"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
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
func ByAttribute[T any](
	config AttributeFamilyConfig,
	extraDefinitionsProvider func(groups attributes.AttrGroups, extraGroupAttributes attributes.GroupAttributes) map[attributes.Section]attributes.AttrReportGroup,
	extraGroupAttributeCfg map[string][]attr.Name,
	getters attributes.NamedGetters[T, string],
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if len(config) == 0 {
			// No filter configuration provided. The node will be ignored
			return swarm.Bypass(input, output)
		}
		f, err := newFilter(config, extraDefinitionsProvider, extraGroupAttributeCfg, getters, input, output)
		if err != nil {
			return nil, err
		}
		return f.doFilter, nil
	}
}

type filter[T any] struct {
	matchers []Matcher[T]
	input    <-chan []T
	output   *msg.Queue[[]T]
}

func newFilter[T any](
	config AttributeFamilyConfig,
	extraDefinitionsProvider func(groups attributes.AttrGroups, extraGroupAttributes attributes.GroupAttributes) map[attributes.Section]attributes.AttrReportGroup,
	extraGroupAttributesCfg map[string][]attr.Name,
	getters attributes.NamedGetters[T, string],
	input, output *msg.Queue[[]T],
) (*filter[T], error) {
	// Internally, from code, we use the OTEL-like naming (attr.Name) for the attributes,
	// which usually uses dot-separation but sometimes also use underscore.
	// Since we allow users to specify metrics in both formats, we convert any user-provided
	// attributes to Prometheus-like, which uniquely uses underscores.
	// Then, to validate the user-provided input, we map the prom-like attributes to
	// our internal representation.
	attrProm2Normal := map[string]attr.Name{}
	for normalizedName := range attributes.AllAttributeNames(extraDefinitionsProvider, extraGroupAttributesCfg) {
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
	return &filter[T]{matchers: matchers, input: input.Subscribe(), output: output}, nil
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
func (f *filter[T]) doFilter(_ context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer f.output.Close()

	for i := range f.input {
		if i = f.filterBatch(i); len(i) > 0 {
			f.output.Send(i)
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
