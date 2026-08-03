// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package transform provides some intermediate nodes that might filter/process/transform the events
package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// UnmatchType defines which actions to do when a route pattern is not recognized
type UnmatchType string

const (
	// UnmatchUnset leaves the Route field as empty
	UnmatchUnset = UnmatchType("unset")
	// UnmatchPath sets the Route field to the same values as the Path
	UnmatchPath = UnmatchType("path")
	// UnmatchWildcard sets the route field to a generic asterisk symbol
	UnmatchWildcard = UnmatchType("wildcard")
	// UnmatchHeuristic detects the route field using a heuristic
	UnmatchHeuristic = UnmatchType("heuristic")
	// UnmatchLowCardinality uses the same classifier as the Heuristic, but
	// it also has a second level Trie based cache to cap the max cardinality
	UnmatchLowCardinality = UnmatchType("low-cardinality")

	UnmatchDefault = UnmatchHeuristic
)

type IgnoreMode string

const (
	// IgnoreMetrics prevents sending metric events for ignored patterns
	IgnoreMetrics = IgnoreMode("metrics")
	// IgnoreTraces prevents sending trace events for ignored patterns
	IgnoreTraces = IgnoreMode("traces")
	// IgnoreAll prevents sending both metrics and traces for ignored patterns
	IgnoreAll = IgnoreMode("all")

	IgnoreDefault = IgnoreAll
)

const wildCard = "/**"

type DirectionalRoutePolicyPresence struct {
	Incoming bool
	Outgoing bool
}

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig struct {
	// Unmatch specifies what to do when a route pattern is not matched.
	// Empty string is treated the same as "wildcard".
	Unmatch UnmatchType `yaml:"unmatched" validate:"omitempty,oneof=unset path wildcard heuristic low-cardinality"`
	// Patterns defines the URL path patterns that will match to a route
	Patterns []string `yaml:"patterns"`
	// Deprecated: To be removed and replaced by a collector-like filtering mechanism
	IgnorePatterns []string `yaml:"ignored_patterns"`
	// Deprecated: To be removed and replaced by a collector-like filtering mechanism
	IgnoredEvents IgnoreMode `yaml:"ignore_mode" validate:"omitempty,oneof=metrics traces all"`
	// Character that will be used to replace route segments
	WildcardChar string `yaml:"wildcard_char,omitempty" jsonschema:"maxLength=1" validate:"max=1"`
	// Max allowed path segment cardinality (per service) for the heuristic matcher
	// 0 = disabled
	MaxPathSegmentCardinality int `yaml:"max_path_segment_cardinality" validate:"gte=0"`

	// Directional is populated only by config v2 conversion. The fields above
	// remain the complete v1 YAML surface.
	Directional *services.DirectionalRoutePolicies `yaml:"-" json:"-"`
	// DirectionalPolicyPresence preserves which global directions were present
	// in a complete v2 config. Nil means both directions are configured.
	DirectionalPolicyPresence *DirectionalRoutePolicyPresence `yaml:"-" json:"-"`
	// DirectionalRuleOnly indicates that Directional provides an inheritance
	// baseline for per-service rules but does not apply globally.
	DirectionalRuleOnly bool `yaml:"-" json:"-"`
}

func (rc *RoutesConfig) Clone() *RoutesConfig {
	if rc == nil {
		return nil
	}
	cloned := *rc
	cloned.Patterns = append([]string(nil), rc.Patterns...)
	cloned.IgnorePatterns = append([]string(nil), rc.IgnorePatterns...)
	if rc.Directional != nil {
		policies := rc.Directional.Clone()
		cloned.Directional = &policies
	}
	if rc.DirectionalPolicyPresence != nil {
		presence := *rc.DirectionalPolicyPresence
		cloned.DirectionalPolicyPresence = &presence
	}
	return &cloned
}

func (rc *RoutesConfig) HasIncomingPolicy() bool {
	return rc != nil && (rc.DirectionalPolicyPresence == nil || rc.DirectionalPolicyPresence.Incoming)
}

func (rc *RoutesConfig) HasOutgoingPolicy() bool {
	return rc != nil && (rc.DirectionalPolicyPresence == nil || rc.DirectionalPolicyPresence.Outgoing)
}

func (rc *RoutesConfig) DirectionalPolicies() services.DirectionalRoutePolicies {
	if rc == nil {
		return services.DirectionalRoutePolicies{}
	}
	if rc.Directional != nil {
		return rc.Directional.Clone()
	}

	policy := services.RoutePolicy{
		Unmatch:                   services.RouteUnmatch(rc.Unmatch),
		Patterns:                  rc.Patterns,
		IgnorePatterns:            rc.IgnorePatterns,
		IgnoredEvents:             services.RouteIgnoreMode(rc.IgnoredEvents),
		WildcardChar:              rc.WildcardChar,
		MaxPathSegmentCardinality: rc.MaxPathSegmentCardinality,
	}
	return services.DirectionalRoutePolicies{
		Incoming: policy.Clone(),
		Outgoing: policy.Clone(),
	}
}

func RoutesProvider(rc *RoutesConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return (&routerNode{
		config: rc,
		input:  input,
		output: output,
	}).provideRoutes
}

type routerNode struct {
	config              *RoutesConfig
	classifier          *clusterurl.ClusterURLClassifier
	classifiers         map[byte]*clusterurl.ClusterURLClassifier
	incomingRoutePolicy *svc.RoutePolicy
	outgoingRoutePolicy *svc.RoutePolicy
	input               *msg.Queue[[]request.Span]
	output              *msg.Queue[[]request.Span]
}

func (rn *routerNode) provideRoutes(_ context.Context) (swarm.RunFunc, error) {
	rc := rn.config
	if rc == nil {
		return swarm.Bypass(rn.input, rn.output)
	}
	if rc.Directional != nil {
		return rn.provideDirectionalRoutes()
	}

	// set default value for Unmatch action
	unmatchAction, err := chooseUnmatchPolicy(rn)
	if err != nil {
		return nil, err
	}
	matcher := route.NewMatcher(rc.Patterns)
	discarder := route.NewMatcher(rc.IgnorePatterns)
	routesEnabled := len(rc.Patterns) > 0
	ignoreEnabled := len(rc.IgnorePatterns) > 0

	ignoreMode := rc.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = IgnoreDefault
	}

	in := rn.input.Subscribe(msg.SubscriberName("transform.Routes"))
	out := rn.output
	return func(ctx context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer rn.output.Close()

		swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
			for i := range spans {
				s := &spans[i]
				if ignoreEnabled {
					if discarder.Find(s.Path) != "" {
						if ignoreMode == IgnoreAll {
							request.SetIgnoreMetrics(s)
							request.SetIgnoreTraces(s)
						}
						// we can't discard it here, ignoring is selective (metrics | traces)
						setSpanIgnoreMode(ignoreMode, s)
					}
				}
				if s.Route == "" && routesEnabled {
					s.Route = matcher.Find(s.Path)
				}
				if s.Route == "" && s.IsHTTPSpan() {
					if s.IsClientSpan() {
						if s.Service.CustomOutRouteMatcher != nil {
							s.Route = s.Service.CustomOutRouteMatcher.Find(s.Path)
						}
					} else {
						if s.Service.CustomInRouteMatcher != nil {
							s.Route = s.Service.CustomInRouteMatcher.Find(s.Path)
						}
					}

					if s.Route == "" && s.Service.HarvestedRouteMatcher != nil {
						s.Route = s.Service.HarvestedRouteMatcher.Find(s.Path)
					}
				}

				unmatchAction(rn, s)
			}
			out.SendCtx(ctx, spans)
		})
	}, nil
}

func (rn *routerNode) provideDirectionalRoutes() (swarm.RunFunc, error) {
	policies := rn.config.DirectionalPolicies()
	rn.incomingRoutePolicy = svc.NewRoutePolicy(policies.Incoming)
	rn.outgoingRoutePolicy = svc.NewRoutePolicy(policies.Outgoing)
	rn.classifiers = map[byte]*clusterurl.ClusterURLClassifier{}

	directionalPolicies := []struct {
		configured bool
		policy     *svc.RoutePolicy
	}{
		{configured: rn.config.HasIncomingPolicy(), policy: rn.incomingRoutePolicy},
		{configured: rn.config.HasOutgoingPolicy(), policy: rn.outgoingRoutePolicy},
	}
	for _, directionalPolicy := range directionalPolicies {
		if !directionalPolicy.configured {
			continue
		}
		policy := directionalPolicy.policy
		if !usesHeuristic(policy.Config.Unmatch) {
			continue
		}
		if _, err := rn.classifierFor(policy.Config); err != nil {
			return nil, err
		}
	}

	in := rn.input.Subscribe(msg.SubscriberName("transform.Routes"))
	out := rn.output
	return func(ctx context.Context) {
		defer rn.output.Close()

		swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
			for i := range spans {
				rn.applyDirectionalPolicy(&spans[i])
			}
			out.SendCtx(ctx, spans)
		})
	}, nil
}

func (rn *routerNode) applyDirectionalPolicy(span *request.Span) {
	if !span.IsHTTPSpan() {
		return
	}

	policy := rn.routePolicy(span)
	if policy == nil {
		return
	}

	ignoreMode := policy.Config.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = services.IgnoreDefault
	}
	if policy.IgnoreMatcher.Find(span.Path) != "" {
		if ignoreMode == services.IgnoreAll {
			request.SetIgnoreMetrics(span)
			request.SetIgnoreTraces(span)
		}
		setSpanIgnoreMode(IgnoreMode(ignoreMode), span)
	}

	if span.Route == "" {
		span.Route = policy.Matcher.Find(span.Path)
	}
	if span.Route == "" && span.IsHTTPSpan() && span.Service.HarvestedRouteMatcher != nil {
		span.Route = span.Service.HarvestedRouteMatcher.Find(span.Path)
	}
	if span.Route != "" {
		return
	}

	switch policy.Config.Unmatch {
	case services.UnmatchUnset:
		return
	case services.UnmatchPath:
		span.Route = span.Path
	case services.UnmatchHeuristic, services.UnmatchLowCardinality:
		if !span.IsHTTPSpan() {
			return
		}
		classifier, err := rn.classifierFor(policy.Config)
		if err != nil {
			slog.With("component", "RoutesProvider").Error("creating route classifier", "error", err)
			span.Route = wildCard
			return
		}
		span.Route = classifier.ClusterURL(span.Path)
		if policy.Config.Unmatch == services.UnmatchLowCardinality {
			if pathTrie := rn.pathTrie(span); pathTrie != nil {
				span.Route = pathTrie.Insert(span.Route)
			}
		}
	case services.UnmatchWildcard, "":
		span.Route = wildCard
	default:
		slog.With("component", "RoutesProvider").Warn(
			"invalid 'unmatch' value in configuration, defaulting to wildcard",
			"value", policy.Config.Unmatch)
		span.Route = wildCard
	}
}

func (rn *routerNode) routePolicy(span *request.Span) *svc.RoutePolicy {
	var servicePolicy, globalPolicy *svc.RoutePolicy
	if span.IsClientSpan() {
		servicePolicy = span.Service.OutgoingRoutePolicy
		globalPolicy = rn.outgoingRoutePolicy
	} else {
		servicePolicy = span.Service.IncomingRoutePolicy
		globalPolicy = rn.incomingRoutePolicy
	}
	if servicePolicy != nil {
		return servicePolicy
	}
	if rn.config.DirectionalRuleOnly {
		return nil
	}
	if span.IsClientSpan() && !rn.config.HasOutgoingPolicy() {
		return nil
	}
	if !span.IsClientSpan() && !rn.config.HasIncomingPolicy() {
		return nil
	}
	return globalPolicy
}

func (rn *routerNode) pathTrie(span *request.Span) *clusterurl.PathTrie {
	if span.IsClientSpan() {
		if span.Service.OutgoingRoutePolicy != nil {
			return span.Service.OutgoingRoutePolicy.PathTrie
		}
		if span.Service.OutgoingPathTrie != nil {
			return span.Service.OutgoingPathTrie
		}
		return rn.outgoingRoutePolicy.PathTrie
	}

	if span.Service.IncomingRoutePolicy != nil {
		return span.Service.IncomingRoutePolicy.PathTrie
	}
	if span.Service.IncomingPathTrie != nil {
		return span.Service.IncomingPathTrie
	}
	return rn.incomingRoutePolicy.PathTrie
}

func (rn *routerNode) classifierFor(policy services.RoutePolicy) (*clusterurl.ClusterURLClassifier, error) {
	wildcard := byte('*')
	if policy.WildcardChar != "" {
		wildcard = policy.WildcardChar[0]
	}
	if classifier := rn.classifiers[wildcard]; classifier != nil {
		return classifier, nil
	}

	classifierCfg := clusterurl.DefaultConfig()
	classifierCfg.ReplaceWith = wildcard
	classifier, err := clusterurl.NewClusterURLClassifier(classifierCfg)
	if err != nil {
		return nil, fmt.Errorf("creating directional route classifier: %w", err)
	}
	rn.classifiers[wildcard] = classifier
	return classifier, nil
}

func usesHeuristic(unmatch services.RouteUnmatch) bool {
	return unmatch == services.UnmatchHeuristic || unmatch == services.UnmatchLowCardinality
}

func makeHeuristicClassifier(rc *RoutesConfig) (*clusterurl.ClusterURLClassifier, error) {
	classifierCfg := clusterurl.DefaultConfig()
	if rc.WildcardChar != "" {
		classifierCfg.ReplaceWith = rc.WildcardChar[0]
	}
	classifier, err := clusterurl.NewClusterURLClassifier(classifierCfg)
	if err != nil {
		return nil, fmt.Errorf("chooseUnmatchPolicy: unable to create cluster URL classifier: %w", err)
	}

	return classifier, nil
}

func chooseUnmatchPolicy(rn *routerNode) (func(rn *routerNode, span *request.Span), error) {
	var unmatchAction func(rn *routerNode, span *request.Span)
	rc := rn.config

	switch rc.Unmatch {
	case UnmatchWildcard, "":
		unmatchAction = setUnmatchToWildcard

		if len(rc.Patterns) == 0 {
			slog.With("component", "RoutesProvider").
				Warn("No route match patterns configured. " +
					"Without route definitions OBI will not be able to generate a low cardinality " +
					"route for trace span names. For optimal experience, please define your application " +
					"HTTP route patterns or enable the route 'heuristic' mode. " +
					"For more information please see the OBI documentation. " +
					"If your application is only using gRPC you can ignore this warning.")
		}
	case UnmatchUnset:
		unmatchAction = leaveUnmatchEmpty
	case UnmatchPath:
		unmatchAction = setUnmatchToPath
	case UnmatchHeuristic:
		classifier, err := makeHeuristicClassifier(rc)
		if err != nil {
			return nil, err
		}
		rn.classifier = classifier
		unmatchAction = classifyFromPath
	case UnmatchLowCardinality:
		classifier, err := makeHeuristicClassifier(rc)
		if err != nil {
			return nil, err
		}
		rn.classifier = classifier
		unmatchAction = classifyFromPathWithCappedCardinality
	default:
		slog.With("component", "RoutesProvider").
			Warn("invalid 'unmatch' value in configuration, defaulting to '"+string(UnmatchDefault)+"'",
				"value", rc.Unmatch)
		unmatchAction = setUnmatchToWildcard
	}

	return unmatchAction, nil
}

func leaveUnmatchEmpty(_ *routerNode, _ *request.Span) {}

func setUnmatchToWildcard(_ *routerNode, str *request.Span) {
	if str.Route == "" {
		str.Route = wildCard
	}
}

func setUnmatchToPath(_ *routerNode, str *request.Span) {
	if str.Route == "" {
		str.Route = str.Path
	}
}

func classifyFromPath(rc *routerNode, s *request.Span) {
	if s.Route == "" && s.IsHTTPSpan() {
		s.Route = rc.classifier.ClusterURL(s.Path)
	}
}

func classifyFromPathWithCappedCardinality(rc *routerNode, s *request.Span) {
	if s.Route == "" && s.IsHTTPSpan() {
		s.Route = rc.classifier.ClusterURL(s.Path)
		if s.Service.PathTrie != nil {
			s.Route = s.Service.PathTrie.Insert(s.Route)
		}
	}
}

func setSpanIgnoreMode(mode IgnoreMode, s *request.Span) {
	switch mode {
	case IgnoreMetrics:
		request.SetIgnoreMetrics(s)
	case IgnoreTraces:
		request.SetIgnoreTraces(s)
	}
}
