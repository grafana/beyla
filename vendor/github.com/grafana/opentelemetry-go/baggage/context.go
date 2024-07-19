// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package baggage // import "github.com/grafana/opentelemetry-go/baggage"

import (
	"context"

	"github.com/grafana/opentelemetry-go/internal/baggage"
)

// ContextWithBaggage returns a copy of parent with baggage.
func ContextWithBaggage(parent context.Context, b Baggage) context.Context {
	// Delegate so any hooks for the OpenTracing bridge are handled.
	return baggage.ContextWithList(parent, b.list)
}

// ContextWithoutBaggage returns a copy of parent with no baggage.
func ContextWithoutBaggage(parent context.Context) context.Context {
	// Delegate so any hooks for the OpenTracing bridge are handled.
	return baggage.ContextWithList(parent, nil)
}

// FromContext returns the baggage contained in ctx.
func FromContext(ctx context.Context) Baggage {
	// Delegate so any hooks for the OpenTracing bridge are handled.
	return Baggage{list: baggage.ListFromContext(ctx)}
}
