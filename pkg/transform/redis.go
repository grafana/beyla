package transform

import (
	"context"
	"fmt"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/transform/regexpcache"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

type RedisConfig struct {
	IgnoreOperations []string           `yaml:"ignored_operations"`
	IgnoredEvents    IgnoreMode         `yaml:"ignore_mode"`
	MatcherConfig    regexpcache.Config `yaml:"matcher"`
}

// TODO(almostinf): add RedisProvider in graphBuilder
func RedisProvider(rc *RedisConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return (&redisNode{
		config: rc,
		input:  input,
		output: output,
	}).provideRedis
}

type redisNode struct {
	config *RedisConfig
	input  *msg.Queue[[]request.Span]
	output *msg.Queue[[]request.Span]
}

func (rn *redisNode) provideRedis(ctx context.Context) (swarm.RunFunc, error) {
	rc := rn.config
	if rc == nil {
		rn.input.Bypass(rn.output)
		return swarm.EmptyRunFunc()
	}

	discarder, err := regexpcache.NewMatcher(rc.MatcherConfig, rc.IgnoreOperations)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize discarder matcher: %w", err)
	}

	ignoreEnabled := len(rc.IgnoreOperations) > 0

	ignoreMode := rc.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = IgnoreDefault
	}

	in := rn.input.Subscribe()
	out := rn.output
	return func(_ context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer rn.output.Close()

		for spans := range in {
			for i := range spans {
				s := &spans[i]
				if !isRedisSpan(s) {
					continue
				}
				if ignoreEnabled {
					// Method is equivalent to a Redis operation
					if discarder.Match(ctx, s.Method) {
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

func isRedisSpan(s *request.Span) bool {
	return s.Type == request.EventTypeRedisClient || s.Type == request.EventTypeRedisServer
}
