// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"net"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// otelUnresolvedHostGetters wraps spanOTELGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func otelUnresolvedHostGetters(unresolvedTag string) func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
		getter, ok := spanOTELGetters(name)
		if name == attr.Client || name == attr.Server {
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if net.ParseIP(kv.Value.AsString()) != nil {
					kv.Value = attribute.StringValue(unresolvedTag)
				}
				return kv
			}, true
		}
		return getter, ok
	}
}

// promUnresolvedHostGetters wraps spanPromGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func promUnresolvedHostGetters(unresolvedTag string) func(name attr.Name) (attributes.Getter[*Span, string], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, string], bool) {
		getter, ok := spanPromGetters(name)
		if name == attr.Client || name == attr.Server {
			return func(span *Span) string {
				val := getter(span)
				if net.ParseIP(val) != nil {
					return unresolvedTag
				}
				return val
			}, true
		}
		return getter, ok
	}
}
