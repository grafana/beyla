// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"log/slog"
	"strconv"

	"go.opentelemetry.io/otel/sdk/trace"
)

// Sampler standard configuration
// https://opentelemetry.io/docs/concepts/sdk-configuration/general-sdk-configuration/#otel_traces_sampler
// We don't support, yet, the jaeger and xray samplers.
type SamplerConfig struct {
	Name string `yaml:"name" env:"OTEL_TRACES_SAMPLER"`
	Arg  string `yaml:"arg" env:"OTEL_TRACES_SAMPLER_ARG"`
}

func (s *SamplerConfig) Implementation() trace.Sampler {
	defaultSampler := func() trace.Sampler {
		return trace.ParentBased(trace.AlwaysSample())
	}
	log := slog.With("component", "otel.Sampler", "name", s.Name, "arg", s.Arg)
	switch s.Name {
	case "always_on":
		return trace.AlwaysSample()
	case "always_off":
		return trace.NeverSample()
	case "traceidratio":
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.TraceIDRatioBased(ratio)
	case "parentbased_always_off":
		return trace.ParentBased(trace.NeverSample())
	case "parentbased_traceidratio":
		ratio, err := strconv.ParseFloat(s.Arg, 64)
		if err != nil {
			log.Warn("can't parse sampler argument. Defaulting to parentbased_always_on", "error", err)
			return defaultSampler()
		}
		return trace.ParentBased(trace.TraceIDRatioBased(ratio))
	case "parentbased_always_on", "":
		return defaultSampler()
	default:
		log.Warn("unsupported sampler name. Defaulting to parentbased_always_on")
		return defaultSampler()
	}
}
