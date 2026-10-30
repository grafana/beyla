// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

// connectionInfoEdge is a locally observed client-to-destination relationship.
type connectionInfoEdge struct {
	client          string
	clientNamespace string
	server          string
	serverNamespace string
}

// connectionInfoEdgeFromSpan derives an edge from one client span when both
// endpoint identities are available. It does not require a matching server span.
func connectionInfoEdgeFromSpan(span *Span) (connectionInfoEdge, bool) {
	if span == nil || !span.IsClientSpan() || span.Service.UID.Name == "" || span.HostName == "" {
		return connectionInfoEdge{}, false
	}

	return connectionInfoEdge{
		client:          span.Service.UID.Name,
		clientNamespace: span.Service.UID.Namespace,
		server:          span.HostName,
		serverNamespace: span.OtherNamespace,
	}, true
}

// HasConnectionInfoEdge reports whether a span has the client-side identity required to emit a connection edge.
func HasConnectionInfoEdge(span *Span) bool {
	_, ok := connectionInfoEdgeFromSpan(span)
	return ok
}
