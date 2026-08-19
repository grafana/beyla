// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"context"
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/filter"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type signalMatcherSets struct {
	traces  filter.MatcherSet[request.Span]
	metrics filter.MatcherSet[request.Span]
}

// InstrumentationFilterSpanGate marks spans as traces or metrics ignored according to
// the filters configured for the instrumentation that produced each span.
func InstrumentationFilterSpanGate(
	config filter.InstrumentationAttributeFamilyConfig,
	extraGroupAttributesCfg map[string][]attr.Name,
	getters attributes.NamedGetters[request.Span, string],
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		matchers, err := instrumentationMatcherSets(config, extraGroupAttributesCfg, getters)
		if err != nil {
			return nil, err
		}
		if len(matchers) == 0 {
			return swarm.Bypass(input, output)
		}

		in := input.Subscribe(msg.SubscriberName("appolly.InstrumentationFilterSpanGate"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(spans []request.Span) {
				applyInstrumentationFilters(matchers, spans)
				output.SendCtx(ctx, spans)
			})
		}, nil
	}
}

func instrumentationMatcherSets(
	config filter.InstrumentationAttributeFamilyConfig,
	extraGroupAttributesCfg map[string][]attr.Name,
	getters attributes.NamedGetters[request.Span, string],
) (map[instrumentations.Instrumentation]signalMatcherSets, error) {
	matchers := make(map[instrumentations.Instrumentation]signalMatcherSets, len(config))
	for instrumentation, signalConfig := range config {
		var signalMatchers signalMatcherSets
		var err error
		if len(signalConfig.Traces) != 0 {
			signalMatchers.traces, err = filter.NewMatcherSet(
				signalConfig.Traces,
				nil,
				extraGroupAttributesCfg,
				getters,
			)
			if err != nil {
				return nil, fmt.Errorf("%s trace filters: %w", instrumentation, err)
			}
		}
		if len(signalConfig.Metrics) != 0 {
			signalMatchers.metrics, err = filter.NewMatcherSet(
				signalConfig.Metrics,
				nil,
				extraGroupAttributesCfg,
				getters,
			)
			if err != nil {
				return nil, fmt.Errorf("%s metric filters: %w", instrumentation, err)
			}
		}
		if len(signalMatchers.traces) != 0 || len(signalMatchers.metrics) != 0 {
			matchers[instrumentation] = signalMatchers
		}
	}
	return matchers, nil
}

func applyInstrumentationFilters(
	matchers map[instrumentations.Instrumentation]signalMatcherSets,
	spans []request.Span,
) {
	for i := range spans {
		instrumentation, ok := spans[i].Type.Instrumentation()
		if !ok {
			continue
		}
		signalMatchers, ok := matchers[instrumentation]
		if !ok {
			continue
		}
		if len(signalMatchers.traces) != 0 && !signalMatchers.traces.Matches(spans[i]) {
			request.SetIgnoreTraces(&spans[i])
		}
		if len(signalMatchers.metrics) != 0 && !signalMatchers.metrics.Matches(spans[i]) {
			request.SetIgnoreMetrics(&spans[i])
		}
	}
}
