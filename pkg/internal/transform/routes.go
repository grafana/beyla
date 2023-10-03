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

const wildCard = "/**"

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig struct {
	// Unmatch specifies what to do when a route pattern is not matched
	Unmatch UnmatchType `yaml:"unmatch"`
	// Patterns of the paths that will match to a route
	Patterns []string `yaml:"patterns"`
}

func RoutesProvider(rc *RoutesConfig) (node.MiddleFunc[[]request.Span, []request.Span], error) {
	// set default value for Unmatch action
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
					"https://grafana.com/docs/grafana-cloud/monitor-applications/beyla/configure/options/#routes-decorator. " +
					"If your application is only using gRPC you can ignore this warning.")
		}
	case UnmatchUnset:
		unmatchAction = leaveUnmatchEmpty
	case UnmatchPath:
		unmatchAction = setUnmatchToPath
	case UnmatchHeuristic: // default
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
	matcher := route.NewMatcher(rc.Patterns)
	return func(in <-chan []request.Span, out chan<- []request.Span) {
		for spans := range in {
			for i := range spans {
				spans[i].Route = matcher.Find(spans[i].Path)
				unmatchAction(&spans[i])
			}
			out <- spans
		}
	}, nil
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
