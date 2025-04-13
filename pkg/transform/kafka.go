package transform

import (
	"context"
	"fmt"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/transform/regexpcache"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
)

type KafkaConfig struct {
	IgnoreTopics  []string           `yaml:"ignored_topics"`
	IgnoredEvents IgnoreMode         `yaml:"ignore_mode"`
	MatcherConfig regexpcache.Config `yaml:"matcher"`
}

// TODO(almostinf): add KafkaProvider in graphBuilder
func KafkaProvider(kc *KafkaConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return (&kafkaNode{
		config: kc,
		input:  input,
		output: output,
	}).provideKafka
}

type kafkaNode struct {
	config *KafkaConfig
	input  *msg.Queue[[]request.Span]
	output *msg.Queue[[]request.Span]
}

func (kn *kafkaNode) provideKafka(ctx context.Context) (swarm.RunFunc, error) {
	kc := kn.config
	if kc == nil {
		kn.input.Bypass(kn.output)
		return swarm.EmptyRunFunc()
	}

	discarder, err := regexpcache.NewMatcher(kc.MatcherConfig, kc.IgnoreTopics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize discarder matcher: %w", err)
	}

	ignoreEnabled := len(kc.IgnoreTopics) > 0

	ignoreMode := kc.IgnoredEvents
	if ignoreMode == "" {
		ignoreMode = IgnoreDefault
	}

	in := kn.input.Subscribe()
	out := kn.output
	return func(_ context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer kn.output.Close()

		for spans := range in {
			for i := range spans {
				s := &spans[i]
				if !isKafkaSpan(s) {
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

func isKafkaSpan(s *request.Span) bool {
	return s.Type == request.EventTypeKafkaClient || s.Type == request.EventTypeKafkaServer
}
