// Package transform provides some intermediate nodes that might filter/process/transform the events
package transform

import (
	"github.com/grafana/http-autoinstrument/pkg/transform/route"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
)

// UnmatchType defines which actions to do when a route pattern is not recognized
type UnmatchType string

const (
	// UnmatchEmpty leaves the Route field as empty
	UnmatchEmpty = UnmatchType("empty")
	// UnmatchPath sets the Route field to the same values as the Path
	UnmatchPath = UnmatchType("path")
	// UnmatchWildcard sets the route field to a generic asterisk symbol
	UnmatchWildcard = UnmatchType("wildcard")

	UnmatchDefault = UnmatchWildcard
)

const wildCard = "*"

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig struct {
	// Unmatch specifies what to do when a route pattern is not
	Unmatch UnmatchType `yaml:"unmatch"`
	// Patterns of the paths that will match to a route
	Patterns []string `yaml:"patterns"`
}

func RoutesProvider(rc *RoutesConfig) node.MiddleFunc[HTTPRequestSpan, HTTPRequestSpan] {
	// set default value for Unmatch action
	var unmatchAction func(span *HTTPRequestSpan)
	switch rc.Unmatch {
	case UnmatchWildcard, "": // default
		unmatchAction = setUnmatchToWildcard
	case UnmatchEmpty:
		unmatchAction = leaveUnmatchEmpty
	case UnmatchPath:
		unmatchAction = setUnmatchToPath
	default:
		slog.With("component", "RoutesProvider").
			Warn("invalid 'unmatch' value in configuration, defaulting to '"+string(UnmatchDefault)+"'",
				"value", rc.Unmatch)
		unmatchAction = setUnmatchToWildcard
	}
	matcher := route.NewMatcher(rc.Patterns)
	return func(in <-chan HTTPRequestSpan, out chan<- HTTPRequestSpan) {
		for s := range in {
			s.Route = matcher.Find(s.Path)
			unmatchAction(&s)
			out <- s
		}
	}
}

func leaveUnmatchEmpty(_ *HTTPRequestSpan) {}

func setUnmatchToWildcard(str *HTTPRequestSpan) {
	if str.Route == "" {
		str.Route = wildCard
	}
}

func setUnmatchToPath(str *HTTPRequestSpan) {
	if str.Route == "" {
		str.Route = str.Path
	}
}
