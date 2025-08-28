// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"context"
	"net"
	"strings"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func IPsFilter(mc *otelcfg.MetricsConfig, input, output *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !mc.DropUnresolvedIPs {
			return swarm.Bypass(input, output)
		}
		in := input.Subscribe()
		return func(_ context.Context) {
			defer output.Close()
			for spans := range in {
				copiedSpans := make([]request.Span, len(spans))
				copy(copiedSpans, spans)

				for i := range copiedSpans {
					span := &copiedSpans[i]
					filterIPsFromSpan(span)
				}
				output.Send(copiedSpans)
			}
		}, nil
	}
}

// filterIPsFromSpan removes IP addresses from span fields when they are unresolved
func filterIPsFromSpan(span *request.Span) {
	// Filter HostName if it's an IP address
	if span.HostName != "" && net.ParseIP(span.HostName) != nil {
		span.HostName = ""
	}

	// Filter Host if it's an IP address and HostName is empty
	if span.HostName == "" && span.Host != "" && net.ParseIP(span.Host) != nil {
		span.Host = ""
	}

	// Filter PeerName if it's an IP address
	if span.PeerName != "" && net.ParseIP(span.PeerName) != nil {
		span.PeerName = ""
	}

	// Filter Peer if it's an IP address and PeerName is empty
	if span.PeerName == "" && span.Peer != "" && net.ParseIP(span.Peer) != nil {
		span.Peer = ""
	}

	// Filter HTTP client host from Statement if it contains IP
	if span.Statement != "" && strings.Contains(span.Statement, request.SchemeHostSeparator) {
		filterHTTPClientHostFromStatement(span)
	}
}

// filterHTTPClientHostFromStatement filters IP addresses from the Statement field for HTTP client spans
func filterHTTPClientHostFromStatement(span *request.Span) {
	if strings.Index(span.Statement, request.SchemeHostSeparator) > 0 {
		schemeHost := strings.Split(span.Statement, request.SchemeHostSeparator)
		if len(schemeHost) >= 2 && schemeHost[1] != "" {
			hostPort := schemeHost[1]

			// Extract host from host:port, handling IPv6 brackets
			host := hostPort
			if strings.HasPrefix(hostPort, "[") {
				// IPv6 with brackets: [2001:db8::1]:8080
				if closeBracket := strings.Index(hostPort, "]"); closeBracket > 0 {
					host = hostPort[1:closeBracket] // Remove brackets
				}
			} else if colonIndex := strings.Index(hostPort, ":"); colonIndex > 0 {
				// IPv4 with port: 192.168.1.1:8080
				host = hostPort[:colonIndex]
			}

			// If host is an IP address, clear the host part from Statement
			if net.ParseIP(host) != nil {
				span.Statement = schemeHost[0] + request.SchemeHostSeparator
			}
		}
	}
}
