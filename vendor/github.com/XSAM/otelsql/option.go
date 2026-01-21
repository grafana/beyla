// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

import (
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

// Option is the interface that applies a configuration option.
type Option interface {
	// Apply sets the Option value of a config.
	Apply(cfg *config)
}

var _ Option = OptionFunc(nil)

// OptionFunc implements the Option interface.
type OptionFunc func(*config)

// Apply sets the Option value of a config by calling the wrapped function.
func (f OptionFunc) Apply(c *config) {
	f(c)
}

// WithTracerProvider specifies a tracer provider to use for creating a tracer.
// If none is specified, the global provider is used.
func WithTracerProvider(provider trace.TracerProvider) Option {
	return OptionFunc(func(cfg *config) {
		cfg.TracerProvider = provider
	})
}

// WithAttributes adds the attributes to each span and measurement.
// If multiple of WithAttributes are passed, the attributes will be extended instead of being overwriting.
func WithAttributes(attributes ...attribute.KeyValue) Option {
	return OptionFunc(func(cfg *config) {
		cfg.Attributes = append(cfg.Attributes, attributes...)
	})
}

// WithSpanNameFormatter takes an interface that will be called on every
// operation and the returned string will become the span name.
func WithSpanNameFormatter(spanNameFormatter SpanNameFormatter) Option {
	return OptionFunc(func(cfg *config) {
		cfg.SpanNameFormatter = spanNameFormatter
	})
}

// WithSpanOptions specifies configuration for span to decide whether to enable some features.
func WithSpanOptions(opts SpanOptions) Option {
	return OptionFunc(func(cfg *config) {
		cfg.SpanOptions = opts
	})
}

// WithMeterProvider specifies a tracer provider to use for creating a tracer.
// If none is specified, the global provider is used.
func WithMeterProvider(provider metric.MeterProvider) Option {
	return OptionFunc(func(cfg *config) {
		cfg.MeterProvider = provider
	})
}

// WithSQLCommenter will enable or disable context propagation for database
// by injecting a comment into SQL statements.
//
// e.g., a SQL query
//
//	SELECT * from FOO
//
// will become
//
//	SELECT * from FOO /*traceparent='00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',tracestate='congo%3Dt61rcWkgMzE%2Crojo%3D00f067aa0ba902b7'*/
//
// This option defaults to disable.
//
// Notice: This option is EXPERIMENTAL and may be changed or removed in a
// later release.
func WithSQLCommenter(enabled bool) Option {
	return OptionFunc(func(cfg *config) {
		cfg.SQLCommenterEnabled = enabled
	})
}

// WithTextMapPropagator specifies a text map propagator to used by the SQLCommenter
// option. If none is specified, the global text map propagator is used.
//
// Notice: This option is EXPERIMENTAL and may be changed or removed in a
// later release.
func WithTextMapPropagator(propagator propagation.TextMapPropagator) Option {
	return OptionFunc(func(cfg *config) {
		cfg.TextMapPropagator = propagator
	})
}

// WithAttributesGetter takes AttributesGetter that will be called on every
// span creations.
func WithAttributesGetter(attributesGetter AttributesGetter) Option {
	return OptionFunc(func(cfg *config) {
		cfg.AttributesGetter = attributesGetter
	})
}

// WithInstrumentAttributesGetter takes InstrumentAttributesGetter that will be called every time metric is recorded to instruments.
func WithInstrumentAttributesGetter(instrumentAttributesGetter InstrumentAttributesGetter) Option {
	return OptionFunc(func(cfg *config) {
		cfg.InstrumentAttributesGetter = instrumentAttributesGetter
	})
}

// WithDisableSkipErrMeasurement controls whether driver.ErrSkip is treated as an error in metrics.
// When enabled, metric measurements with driver.ErrSkip will be recorded as status=ok instead of error.
//
// This option does not affect span error recording. To suppress driver.ErrSkip in spans, use
// WithSpanOptions(SpanOptions{DisableErrSkip: true}).
func WithDisableSkipErrMeasurement(disable bool) Option {
	return OptionFunc(func(cfg *config) {
		cfg.DisableSkipErrMeasurement = disable
	})
}

// WithInstrumentErrorAttributesGetter takes InstrumentErrorAttributesGetter that will be called every time metric is recorded to instruments.
func WithInstrumentErrorAttributesGetter(instrumentErrorAttributesGetter InstrumentErrorAttributesGetter) Option {
	return OptionFunc(func(cfg *config) {
		cfg.InstrumentErrorAttributesGetter = instrumentErrorAttributesGetter
	})
}
