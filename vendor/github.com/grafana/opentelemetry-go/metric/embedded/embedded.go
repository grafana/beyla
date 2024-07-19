// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package embedded provides interfaces embedded within the [OpenTelemetry
// metric API].
//
// Implementers of the [OpenTelemetry metric API] can embed the relevant type
// from this package into their implementation directly. Doing so will result
// in a compilation error for users when the [OpenTelemetry metric API] is
// extended (which is something that can happen without a major version bump of
// the API package).
//
// [OpenTelemetry metric API]: https://pkg.go.dev/github.com/grafana/opentelemetry-go/metric
package embedded // import "github.com/grafana/opentelemetry-go/metric/embedded"

// MeterProvider is embedded in
// [github.com/grafana/opentelemetry-go/metric.MeterProvider].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.MeterProvider] if you want users to
// experience a compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.MeterProvider]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type MeterProvider interface{ meterProvider() }

// Meter is embedded in [github.com/grafana/opentelemetry-go/metric.Meter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Meter] if you want users to experience a
// compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.Meter] interface
// is extended (which is something that can happen without a major version bump
// of the API package).
type Meter interface{ meter() }

// Float64Observer is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64Observer].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64Observer] if you want
// users to experience a compilation error, signaling they need to update to
// your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64Observer] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Float64Observer interface{ float64Observer() }

// Int64Observer is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64Observer].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64Observer] if you want users
// to experience a compilation error, signaling they need to update to your
// latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64Observer] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Int64Observer interface{ int64Observer() }

// Observer is embedded in [github.com/grafana/opentelemetry-go/metric.Observer].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Observer] if you want users to experience a
// compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.Observer]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Observer interface{ observer() }

// Registration is embedded in [github.com/grafana/opentelemetry-go/metric.Registration].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Registration] if you want users to
// experience a compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.Registration]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Registration interface{ registration() }

// Float64Counter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64Counter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64Counter] if you want
// users to experience a compilation error, signaling they need to update to
// your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64Counter] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Float64Counter interface{ float64Counter() }

// Float64Histogram is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64Histogram].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64Histogram] if you want
// users to experience a compilation error, signaling they need to update to
// your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64Histogram] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Float64Histogram interface{ float64Histogram() }

// Float64Gauge is embedded in [github.com/grafana/opentelemetry-go/metric.Float64Gauge].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64Gauge] if you want users to
// experience a compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.Float64Gauge]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Float64Gauge interface{ float64Gauge() }

// Float64ObservableCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableCounter] if you
// want users to experience a compilation error, signaling they need to update
// to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableCounter]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Float64ObservableCounter interface{ float64ObservableCounter() }

// Float64ObservableGauge is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableGauge].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableGauge] if you
// want users to experience a compilation error, signaling they need to update
// to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableGauge]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Float64ObservableGauge interface{ float64ObservableGauge() }

// Float64ObservableUpDownCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableUpDownCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableUpDownCounter]
// if you want users to experience a compilation error, signaling they need to
// update to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64ObservableUpDownCounter]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Float64ObservableUpDownCounter interface{ float64ObservableUpDownCounter() }

// Float64UpDownCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Float64UpDownCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Float64UpDownCounter] if you
// want users to experience a compilation error, signaling they need to update
// to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Float64UpDownCounter] interface
// is extended (which is something that can happen without a major version bump
// of the API package).
type Float64UpDownCounter interface{ float64UpDownCounter() }

// Int64Counter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64Counter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64Counter] if you want users
// to experience a compilation error, signaling they need to update to your
// latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64Counter] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Int64Counter interface{ int64Counter() }

// Int64Histogram is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64Histogram].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64Histogram] if you want
// users to experience a compilation error, signaling they need to update to
// your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64Histogram] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Int64Histogram interface{ int64Histogram() }

// Int64Gauge is embedded in [github.com/grafana/opentelemetry-go/metric.Int64Gauge].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64Gauge] if you want users to experience
// a compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/metric.Int64Gauge]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Int64Gauge interface{ int64Gauge() }

// Int64ObservableCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableCounter] if you
// want users to experience a compilation error, signaling they need to update
// to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableCounter]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Int64ObservableCounter interface{ int64ObservableCounter() }

// Int64ObservableGauge is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableGauge].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableGauge] if you
// want users to experience a compilation error, signaling they need to update
// to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableGauge] interface
// is extended (which is something that can happen without a major version bump
// of the API package).
type Int64ObservableGauge interface{ int64ObservableGauge() }

// Int64ObservableUpDownCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableUpDownCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableUpDownCounter] if
// you want users to experience a compilation error, signaling they need to
// update to your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64ObservableUpDownCounter]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type Int64ObservableUpDownCounter interface{ int64ObservableUpDownCounter() }

// Int64UpDownCounter is embedded in
// [github.com/grafana/opentelemetry-go/metric.Int64UpDownCounter].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/metric.Int64UpDownCounter] if you want
// users to experience a compilation error, signaling they need to update to
// your latest implementation, when the
// [github.com/grafana/opentelemetry-go/metric.Int64UpDownCounter] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Int64UpDownCounter interface{ int64UpDownCounter() }
