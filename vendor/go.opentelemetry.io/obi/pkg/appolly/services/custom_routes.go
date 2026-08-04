// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

type RouteUnmatch string

const (
	UnmatchUnset          = RouteUnmatch("unset")
	UnmatchPath           = RouteUnmatch("path")
	UnmatchWildcard       = RouteUnmatch("wildcard")
	UnmatchHeuristic      = RouteUnmatch("heuristic")
	UnmatchLowCardinality = RouteUnmatch("low-cardinality")
	UnmatchDefault        = UnmatchHeuristic
)

type RouteIgnoreMode string

const (
	IgnoreMetrics = RouteIgnoreMode("metrics")
	IgnoreTraces  = RouteIgnoreMode("traces")
	IgnoreAll     = RouteIgnoreMode("all")
	IgnoreDefault = IgnoreAll
)

// RoutePolicy configures route handling for one traffic direction.
type RoutePolicy struct {
	Unmatch                   RouteUnmatch
	Patterns                  []string
	IgnorePatterns            []string
	IgnoredEvents             RouteIgnoreMode
	WildcardChar              string
	MaxPathSegmentCardinality int
}

// RoutePolicyOverride preserves whether a v2 refinement field was omitted.
type RoutePolicyOverride struct {
	Unmatch                   *RouteUnmatch
	Patterns                  *[]string
	IgnorePatterns            *[]string
	IgnoredEvents             *RouteIgnoreMode
	WildcardChar              *string
	MaxPathSegmentCardinality *int
}

type DirectionalRoutePolicies struct {
	Incoming RoutePolicy
	Outgoing RoutePolicy
}

type DirectionalRoutePolicyOverrides struct {
	Incoming *RoutePolicyOverride
	Outgoing *RoutePolicyOverride
}

type CustomRoutesConfig struct {
	Incoming []string `yaml:"incoming"`
	Outgoing []string `yaml:"outgoing"`

	// PolicyOverrides is populated only by config v2 conversion. The legacy
	// fields above remain the complete v1 YAML surface.
	PolicyOverrides *DirectionalRoutePolicyOverrides `yaml:"-" json:"-"`
}

func (p RoutePolicy) Clone() RoutePolicy {
	p.Patterns = cloneRouteStrings(p.Patterns)
	p.IgnorePatterns = cloneRouteStrings(p.IgnorePatterns)
	return p
}

func (p DirectionalRoutePolicies) Clone() DirectionalRoutePolicies {
	return DirectionalRoutePolicies{
		Incoming: p.Incoming.Clone(),
		Outgoing: p.Outgoing.Clone(),
	}
}

func (o *RoutePolicyOverride) Apply(base RoutePolicy) RoutePolicy {
	if o == nil {
		return base.Clone()
	}

	result := base.Clone()
	if o.Unmatch != nil {
		result.Unmatch = *o.Unmatch
	}
	if o.Patterns != nil {
		result.Patterns = cloneRouteStrings(*o.Patterns)
	}
	if o.IgnorePatterns != nil {
		result.IgnorePatterns = cloneRouteStrings(*o.IgnorePatterns)
	}
	if o.IgnoredEvents != nil {
		result.IgnoredEvents = *o.IgnoredEvents
	}
	if o.WildcardChar != nil {
		result.WildcardChar = *o.WildcardChar
	}
	if o.MaxPathSegmentCardinality != nil {
		result.MaxPathSegmentCardinality = *o.MaxPathSegmentCardinality
	}
	return result
}

func (o *DirectionalRoutePolicyOverrides) Apply(base DirectionalRoutePolicies) DirectionalRoutePolicies {
	if o == nil {
		return base.Clone()
	}

	return DirectionalRoutePolicies{
		Incoming: o.Incoming.Apply(base.Incoming),
		Outgoing: o.Outgoing.Apply(base.Outgoing),
	}
}

func cloneRouteStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return append([]string(nil), in...)
}
