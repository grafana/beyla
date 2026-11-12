// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services // import "go.opentelemetry.io/obi/pkg/appolly/services"

type GoExceptionsConfig struct {
	// Omitted panics defaults to enabled when exception capture is enabled.
	Panics          *bool `yaml:"panics,omitempty"`
	FormattedErrors bool  `yaml:"formatted_errors"`
}

func (c GoExceptionsConfig) PanicsEnabled() bool {
	return c.Panics == nil || *c.Panics
}

// ExceptionsConfig controls runtime exception acquisition independently of trace export.
type ExceptionsConfig struct {
	Enabled bool               `yaml:"enabled"`
	Go      GoExceptionsConfig `yaml:"go"`
}

// GoExceptionsOverride inherits each omitted option from the global settings.
type GoExceptionsOverride struct {
	Panics          *bool `yaml:"panics,omitempty"`
	FormattedErrors *bool `yaml:"formatted_errors,omitempty"`
}

// ExceptionsOverride preserves omission separately from explicitly disabled capture.
type ExceptionsOverride struct {
	Enabled *bool                 `yaml:"enabled,omitempty"`
	Go      *GoExceptionsOverride `yaml:"go,omitempty"`
}

// Resolve applies a workload override to global defaults.
func (o *ExceptionsOverride) Resolve(defaults ExceptionsConfig) ExceptionsConfig {
	if o == nil {
		return defaults
	}
	if o.Enabled != nil {
		defaults.Enabled = *o.Enabled
	}
	if o.Go != nil {
		if o.Go.Panics != nil {
			defaults.Go.Panics = o.Go.Panics
		}
		if o.Go.FormattedErrors != nil {
			defaults.Go.FormattedErrors = *o.Go.FormattedErrors
		}
	}
	return defaults
}
