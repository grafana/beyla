// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
)

// SpanOTELGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanOTELGetters(renameUnresolved string) attributes.NamedGetters[*Span, attribute.KeyValue] {
	if renameUnresolved == "" {
		return spanOTELGetters
	}
	return otelUnresolvedHostGetters(renameUnresolved)
}

// SpanPromGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanPromGetters(renameUnresolved string) attributes.NamedGetters[*Span, string] {
	if renameUnresolved == "" {
		return spanPromGetters
	}
	return promUnresolvedHostGetters(renameUnresolved)
}
