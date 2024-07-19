// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package embedded provides interfaces embedded within the [OpenTelemetry
// trace API].
//
// Implementers of the [OpenTelemetry trace API] can embed the relevant type
// from this package into their implementation directly. Doing so will result
// in a compilation error for users when the [OpenTelemetry trace API] is
// extended (which is something that can happen without a major version bump of
// the API package).
//
// [OpenTelemetry trace API]: https://pkg.go.dev/github.com/grafana/opentelemetry-go/trace
package embedded // import "github.com/grafana/opentelemetry-go/trace/embedded"

// TracerProvider is embedded in
// [github.com/grafana/opentelemetry-go/trace.TracerProvider].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/trace.TracerProvider] if you want users to
// experience a compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/trace.TracerProvider]
// interface is extended (which is something that can happen without a major
// version bump of the API package).
type TracerProvider interface{ tracerProvider() }

// Tracer is embedded in [github.com/grafana/opentelemetry-go/trace.Tracer].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/trace.Tracer] if you want users to experience a
// compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/trace.Tracer] interface
// is extended (which is something that can happen without a major version bump
// of the API package).
type Tracer interface{ tracer() }

// Span is embedded in [github.com/grafana/opentelemetry-go/trace.Span].
//
// Embed this interface in your implementation of the
// [github.com/grafana/opentelemetry-go/trace.Span] if you want users to experience a
// compilation error, signaling they need to update to your latest
// implementation, when the [github.com/grafana/opentelemetry-go/trace.Span] interface is
// extended (which is something that can happen without a major version bump of
// the API package).
type Span interface{ span() }
