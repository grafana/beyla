package transform

import (
	"context"
	"fmt"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/transform/regexpcache"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

type SQLConfig struct {
	IgnoreTables  []string           `yaml:"ignored_tables"`
	IgnoredEvents IgnoreMode         `yaml:"ignore_mode"`
	MatcherConfig regexpcache.Config `yaml:"matcher"`
}

// TODO(almostinf): add SQLProvider in graphBuilder
func SQLProvider(sc *SQLConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return (&sqlNode{
		config: sc,
		input:  input,
		output: output,
	}).provideSQL
}

type sqlNode struct {
	config *SQLConfig
	input  *msg.Queue[[]request.Span]
	output *msg.Queue[[]request.Span]
}

func (sn *sqlNode) provideSQL(ctx context.Context) (swarm.RunFunc, error) {
	sc := sn.config
	if sc == nil {
		sn.input.Bypass(sn.output)
		return swarm.EmptyRunFunc()
	}

	discarder, err := regexpcache.NewMatcher(sc.MatcherConfig, sc.IgnoreTables)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize discarder matcher: %w", err)
	}

	ignoreEnabled := len(sc.IgnoreTables) > 0

	ignoreMode := sc.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = IgnoreDefault
	}

	in := sn.input.Subscribe()
	out := sn.output
	return func(_ context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer sn.output.Close()

		for spans := range in {
			for i := range spans {
				s := &spans[i]
				if !isSQLSpan(s) {
					continue
				}
				if ignoreEnabled {
					if discarder.Match(ctx, s.Path) {
						if ignoreMode == IgnoreAll {
							s.SetIgnoreMetrics()
							s.SetIgnoreTraces()
						}
						// we can't discard it here, ignoring is selective (metrics | traces)
						setSpanIgnoreMode(ignoreMode, s)
					}
				}
			}
			out.Send(spans)
		}
	}, nil
}

func isSQLSpan(s *request.Span) bool {
	return s.Type == request.EventTypeSQLClient
}
