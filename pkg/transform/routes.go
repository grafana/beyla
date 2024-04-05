// Package transform provides some intermediate nodes that might filter/process/transform the events
package transform

import (
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/transform/route"
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

	UnmatchDefault = UnmatchWildcard
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

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig struct {
	// Unmatch specifies what to do when a route pattern is not matched
	Unmatch UnmatchType `yaml:"unmatched"`
	// Patterns of the paths that will match to a route
	Patterns       []string   `yaml:"patterns"`
	IgnorePatterns []string   `yaml:"ignored_patterns"`
	IgnoredEvents  IgnoreMode `yaml:"ignore_mode"`
}

func RoutesProvider(rc *RoutesConfig) (node.MiddleFunc[[]request.Span, []request.Span], error) {
	// set default value for Unmatch action
	unmatchAction, err := chooseUnmatchPolicy(rc)
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

	return func(in <-chan []request.Span, out chan<- []request.Span) {
		for spans := range in {
			filtered := make([]request.Span, 0, len(spans))
			for i := range spans {
				s := &spans[i]
				if ignoreEnabled {
					if discarder.Find(s.Path) != "" {
						if ignoreMode == IgnoreAll {
							continue
						}
						// we can't discard it here, ignoring is selective (metrics | traces)
						setSpanIgnoreMode(ignoreMode, s)
					}
				}
				if routesEnabled {
					s.Route = matcher.Find(s.Path)
				}
				unmatchAction(s)
				filtered = append(filtered, *s)
			}
			if len(filtered) > 0 {
				out <- filtered
			}
		}
	}, nil
}

func chooseUnmatchPolicy(rc *RoutesConfig) (func(span *request.Span), error) {
	var unmatchAction func(span *request.Span)

	switch rc.Unmatch {
	case UnmatchWildcard, "":
		unmatchAction = setUnmatchToWildcard

		if len(rc.Patterns) == 0 {
			slog.With("component", "RoutesProvider").
				Warn("No route match patterns configured. " +
					"Without route definitions Beyla will not be able to generate a low cardinality " +
					"route for trace span names. For optimal experience, please define your application " +
					"HTTP route patterns or enable the route 'heuristic' mode. " +
					"For more information please see the documentation at: " +
					"https://grafana.com/docs/beyla/latest/configure/options/#routes-decorator . " +
					"If your application is only using gRPC you can ignore this warning.")
		}
	case UnmatchUnset:
		unmatchAction = leaveUnmatchEmpty
	case UnmatchPath:
		unmatchAction = setUnmatchToPath
	case UnmatchHeuristic:
		err := route.InitAutoClassifier()
		if err != nil {
			return nil, err
		}
		unmatchAction = classifyFromPath
	default:
		slog.With("component", "RoutesProvider").
			Warn("invalid 'unmatch' value in configuration, defaulting to '"+string(UnmatchDefault)+"'",
				"value", rc.Unmatch)
		unmatchAction = setUnmatchToWildcard
	}

	return unmatchAction, nil
}

func leaveUnmatchEmpty(_ *request.Span) {}

func setUnmatchToWildcard(str *request.Span) {
	if str.Route == "" {
		str.Route = wildCard
	}
}

func setUnmatchToPath(str *request.Span) {
	if str.Route == "" {
		str.Route = str.Path
	}
}

func classifyFromPath(s *request.Span) {
	if s.Route == "" && (s.Type == request.EventTypeHTTP || s.Type == request.EventTypeHTTPClient) {
		s.Route = route.ClusterPath(s.Path)
	}
}

func setSpanIgnoreMode(mode IgnoreMode, s *request.Span) {
	switch mode {
	case IgnoreMetrics:
		s.IgnoreSpan = request.IgnoreMetrics
	case IgnoreTraces:
		s.IgnoreSpan = request.IgnoreTraces
	}
}
