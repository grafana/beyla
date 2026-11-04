// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

// ExceptionsConfig controls runtime exception acquisition independently of trace export.
type ExceptionsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ExceptionsOverride preserves omission separately from explicitly disabled capture.
type ExceptionsOverride struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// Resolve applies a workload override to global defaults.
func (o *ExceptionsOverride) Resolve(defaults ExceptionsConfig) ExceptionsConfig {
	if o == nil {
		return defaults
	}
	if o.Enabled != nil {
		defaults.Enabled = *o.Enabled
	}
	return defaults
}
