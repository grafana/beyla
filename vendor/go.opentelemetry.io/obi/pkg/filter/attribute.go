// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func aflog() *slog.Logger {
	return slog.With("component", "filter.ByAttribute")
}

// AttributesConfig stores the user-provided section for filtering either Application or Network
// records by attribute values
type AttributesConfig struct {
	Application                  AttributeFamilyConfig                `yaml:"application"`
	ApplicationByInstrumentation InstrumentationAttributeFamilyConfig `yaml:"-" env:"-" json:"-"`
	Network                      AttributeFamilyConfig                `yaml:"network"`
	Stats                        AttributeFamilyConfig                `yaml:"stats"`
}

// AttributeFamilyConfig maps, for a given record, each attribute with its MatchDefinition
type AttributeFamilyConfig map[string]MatchDefinition

// SignalAttributeFamilyConfig groups attribute filters by telemetry signal.
type SignalAttributeFamilyConfig struct {
	Traces  AttributeFamilyConfig
	Metrics AttributeFamilyConfig
}

// InstrumentationAttributeFamilyConfig groups signal filters by instrumentation.
type InstrumentationAttributeFamilyConfig map[instrumentations.Instrumentation]SignalAttributeFamilyConfig

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
	matchers MatcherSet[T]
	input    <-chan []T
	output   *msg.Queue[[]T]
}

// MatcherSet matches a record when all of its configured attribute matchers match.
type MatcherSet[T any] []Matcher[T]

func newFilter[T any](
	config AttributeFamilyConfig,
	extraDefinitionsProvider func(groups attributes.AttrGroups, extraGroupAttributes attributes.GroupAttributes) map[attributes.Section]attributes.AttrReportGroup,
	extraGroupAttributesCfg map[string][]attr.Name,
	getters attributes.NamedGetters[T, string],
	input, output *msg.Queue[[]T],
) (*filter[T], error) {
	matchers, err := NewMatcherSet(
		config,
		extraDefinitionsProvider,
		extraGroupAttributesCfg,
		getters,
	)
	if err != nil {
		return nil, err
	}
	return &filter[T]{
		matchers: matchers,
		input:    input.Subscribe(msg.SubscriberName("AttributesFilter")),
		output:   output,
	}, nil
}

// NewMatcherSet validates an attribute filter configuration and compiles its matchers.
func NewMatcherSet[T any](
	config AttributeFamilyConfig,
	extraDefinitionsProvider func(groups attributes.AttrGroups, extraGroupAttributes attributes.GroupAttributes) map[attributes.Section]attributes.AttrReportGroup,
	extraGroupAttributesCfg map[string][]attr.Name,
	getters attributes.NamedGetters[T, string],
) (MatcherSet[T], error) {
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
	matchers := make(MatcherSet[T], 0, len(config))
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
	return matchers, nil
}

// Matches reports whether all configured attribute matchers match record.
func (m MatcherSet[T]) Matches(record T) bool {
	for i := range m {
		if !m[i].Matches(record) {
			return false
		}
	}
	return true
}

// buildMatcher returns a Matcher given an attribute name, the user-provided MatchDefinition, and the provided
// list of getters for a given record type T.
func buildMatcher[T any](getters attributes.NamedGetters[T, string], attribute attr.Name, def *MatchDefinition) (Matcher[T], error) {
	m := Matcher[T]{}
	if err := def.Validate(); err != nil {
		return m, err
	}
	switch {
	case def.Match != "":
		var err error
		if m.Glob, err = glob.Compile(def.Match); err != nil {
			return m, fmt.Errorf("invalid glob in match property: %w", err)
		}
	case def.NotMatch != "":
		var err error
		if m.Glob, err = glob.Compile(def.NotMatch); err != nil {
			return m, fmt.Errorf("invalid glob in not_match property: %w", err)
		}
		m.Negate = true
	default:
		// use match-all as dummy for numeric-only comparisons
		m.Glob = glob.MustCompile("*")

		// Set up numeric comparisons
		if def.Equals != nil {
			m.Equals = def.Equals
		}
		if def.NotEquals != nil {
			m.NotEquals = def.NotEquals
		}
		if def.GreaterEquals != nil {
			m.GreaterEquals = def.GreaterEquals
		}
		if def.GreaterThan != nil {
			m.GreaterThan = def.GreaterThan
		}
		if def.LessEquals != nil {
			m.LessEquals = def.LessEquals
		}
		if def.LessThan != nil {
			m.LessThan = def.LessThan
		}
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
func (f *filter[T]) doFilter(ctx context.Context) {
	// output channel must be closed so later stages in the pipeline can finish in cascade
	defer f.output.Close()

	swarms.ForEachInput(ctx, f.input, aflog().Debug, func(attrs []T) {
		if attrs = f.filterBatch(attrs); len(attrs) > 0 {
			f.output.SendCtx(ctx, attrs)
		}
	})
}

// filterBatch removes from the input slice the records that do not match
// the user-provided attribute matchers
func (f *filter[T]) filterBatch(batch []T) []T {
	w := 0
	for t := range batch {
		if !f.matchers.Matches(batch[t]) {
			continue
		}
		batch[w] = batch[t]
		w++
	}
	return batch[:w]
}
