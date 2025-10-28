// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"net"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func willReplaceIP(value, replacement string) bool {
	return replacement != "" && net.ParseIP(value) != nil
}

func unresolvedValue(value, replacement string) string {
	if replacement != "" {
		if net.ParseIP(value) != nil {
			return replacement
		}
	}

	return value
}

// otelUnresolvedHostGetters wraps spanOTELGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func otelUnresolvedHostGetters(unresolved UnresolvedNames) func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
		getter, ok := spanOTELGetters(name)
		switch name {
		case attr.Client:
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if s.IsClientSpan() {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Generic))
				} else {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Incoming))
				}
				return kv
			}, true
		case attr.Server:
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if s.IsClientSpan() {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Outgoing))
				} else {
					kv.Value = attribute.StringValue(unresolvedValue(kv.Value.AsString(), unresolved.Generic))
				}
				return kv
			}, true
		case attr.ClientNamespace:
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if !s.IsClientSpan() {
					currentNs := kv.Value.AsString()
					if currentNs == "" && willReplaceIP(SpanPeer(s), unresolved.Incoming) {
						kv.Value = attribute.StringValue(s.Service.UID.Namespace)
					}
				}
				return kv
			}, true
		case attr.ServerNamespace:
			return func(s *Span) attribute.KeyValue {
				kv := getter(s)
				if s.IsClientSpan() {
					currentNs := kv.Value.AsString()
					if currentNs == "" && willReplaceIP(SpanHost(s), unresolved.Outgoing) {
						kv.Value = attribute.StringValue(s.Service.UID.Namespace)
					}
				}
				return kv
			}, true
		}

		return getter, ok
	}
}

// promUnresolvedHostGetters wraps spanPromGetters but replacing client and server address
// unresolved metrics by a user-provided tag (usually "unresolved")
func promUnresolvedHostGetters(unresolved UnresolvedNames) func(name attr.Name) (attributes.Getter[*Span, string], bool) {
	return func(name attr.Name) (attributes.Getter[*Span, string], bool) {
		getter := spanPromGetters(name)
		switch name {
		case attr.Client:
			return func(span *Span) string {
				val := getter(span)
				if span.IsClientSpan() {
					return unresolvedValue(val, unresolved.Generic)
				}
				return unresolvedValue(val, unresolved.Incoming)
			}, true
		case attr.Server:
			return func(span *Span) string {
				val := getter(span)
				if span.IsClientSpan() {
					return unresolvedValue(val, unresolved.Outgoing)
				}
				return unresolvedValue(val, unresolved.Generic)
			}, true
		case attr.ClientNamespace:
			return func(span *Span) string {
				val := getter(span)
				if !span.IsClientSpan() {
					if val == "" && willReplaceIP(SpanPeer(span), unresolved.Incoming) {
						return span.Service.UID.Namespace
					}
				}
				return val
			}, true
		case attr.ServerNamespace:
			return func(span *Span) string {
				val := getter(span)
				if span.IsClientSpan() {
					if val == "" && willReplaceIP(SpanHost(span), unresolved.Outgoing) {
						return span.Service.UID.Namespace
					}
				}
				return val
			}, true
		}
		return getter, true
	}
}
