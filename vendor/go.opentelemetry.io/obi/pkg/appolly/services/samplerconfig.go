// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

import (
	"log/slog"
	"strconv"

	"go.opentelemetry.io/otel/sdk/trace"
)

type SamplerName string

const (
	SamplerAlwaysOn                SamplerName = "always_on"
	SamplerAlwaysOff               SamplerName = "always_off"
	SamplerTraceIDRatio            SamplerName = "traceidratio"
	SamplerParentBasedAlwaysOn     SamplerName = "parentbased_always_on"
	SamplerParentBasedAlwaysOff    SamplerName = "parentbased_always_off"
	SamplerParentBasedTraceIDRatio SamplerName = "parentbased_traceidratio"
)

// Sampler standard configuration
// https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler
// We don't support, yet, the jaeger and xray samplers.
type SamplerConfig struct {
	Name SamplerName `yaml:"name" env:"OTEL_TRACES_SAMPLER"`
	Arg  string      `yaml:"arg" env:"OTEL_TRACES_SAMPLER_ARG"`
}

func (s *SamplerConfig) Implementation() trace.Sampler {
	defaultSampler := func() trace.Sampler {
		return trace.ParentBased(trace.AlwaysSample())
	}
	log := slog.With("component", "otel.Sampler", "name", s.Name, "arg", s.Arg)
	switch s.Name {
	case SamplerAlwaysOn:
		return trace.AlwaysSample()
	case SamplerAlwaysOff:
		return trace.NeverSample()
	case SamplerTraceIDRatio:
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.TraceIDRatioBased(ratio)
	case SamplerParentBasedAlwaysOff:
		return trace.ParentBased(trace.NeverSample())
	case SamplerParentBasedTraceIDRatio:
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	case SamplerParentBasedAlwaysOn, "":
		return defaultSampler()
	default:
		log.Warn("unsupported sampler name. Defaulting to parentbased_always_on")
		return defaultSampler()
	}
}
