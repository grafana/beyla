// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

type UnresolvedNames struct {
	Generic  string
	Outgoing string
	Incoming string
}

// SpanOTELGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanOTELGetters(unresolved UnresolvedNames) attributes.NamedGetters[*Span, attribute.KeyValue] {
	return otelUnresolvedHostGetters(unresolved)
}

// SpanPromGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanPromGetters(unresolved UnresolvedNames) attributes.NamedGetters[*Span, string] {
	return promUnresolvedHostGetters(unresolved)
}
