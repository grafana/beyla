// Package transform provides some intermediate nodes that might filter/process/transform the events
package transform

import (
	"context"
	"log/slog"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/transform/route"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
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

// RoutesConfig allows grouping URLs sharing a given pattern.
type RoutesConfig struct {
	// Unmatch specifies what to do when a route pattern is not matched
	Unmatch UnmatchType `yaml:"unmatched"`
	// Patterns of the paths that will match to a route
	Patterns []string `yaml:"patterns"`
	// Deprecated. To be removed and replaced by a collector-like filtering mechanism
	IgnorePatterns []string `yaml:"ignored_patterns"`
	// Deprecated. To be removed and replaced by a collector-like filtering mechanism
	IgnoredEvents IgnoreMode `yaml:"ignore_mode"`
	// Character that will be used to replace route segments
	WildcardChar string `yaml:"wildcard_char,omitempty"`
}

func RoutesProvider(rc *RoutesConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return (&routerNode{
		config: rc,
		input:  input,
		output: output,
	}).provideRoutes
}

type routerNode struct {
	config *RoutesConfig
	input  *msg.Queue[[]request.Span]
	output *msg.Queue[[]request.Span]
}

func (rn *routerNode) provideRoutes(_ context.Context) (swarm.RunFunc, error) {
	rc := rn.config
	if rc == nil {
		return swarm.Bypass(rn.input, rn.output)
	}

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

	in := rn.input.Subscribe()
	out := rn.output
	return func(ctx context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer rn.output.Close()

		for {
			select {
			case <-ctx.Done():
				return
			case spans := <-in:
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
					if routesEnabled {
						s.Route = matcher.Find(s.Path)
					}
					unmatchAction(rc, s)
				}
				out.Send(spans)
			}
		}
	}, nil
}

func chooseUnmatchPolicy(rc *RoutesConfig) (func(rc *RoutesConfig, span *request.Span), error) {
	var unmatchAction func(rc *RoutesConfig, span *request.Span)

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
					"https://grafana.com/docs/beyla/latest/configure/options/#routes-decorator. " +
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

func leaveUnmatchEmpty(_ *RoutesConfig, _ *request.Span) {}

func setUnmatchToWildcard(_ *RoutesConfig, str *request.Span) {
	if str.Route == "" {
		str.Route = wildCard
	}
}

func setUnmatchToPath(_ *RoutesConfig, str *request.Span) {
	if str.Route == "" {
		str.Route = str.Path
	}
}

func classifyFromPath(rc *RoutesConfig, s *request.Span) {
	if s.Route == "" && (s.Type == request.EventTypeHTTP || s.Type == request.EventTypeHTTPClient) {
		s.Route = route.ClusterPath(s.Path, rc.WildcardChar[0])
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
