// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

type Service struct {
	Name         string
	Namespace    string
	ServiceGraph bool
}

type Endpoint struct {
	IP   string
	Port int
}

type Listener struct {
	Endpoint Endpoint
	Service  Service
}

type CallerService struct {
	Service         Service
	RemainingMillis int64
}

type Caller struct {
	Destination Endpoint
	Services    []CallerService
}

// Relative lifetimes avoid requiring synchronized clocks between agents.
type Snapshot struct {
	Hostname              string
	Services              []Service
	Listeners             []Listener
	Callers               []Caller
	KnownCallers          []Caller
	MetricProtocols       *instrumentations.InstrumentationSelection
	CallerAmbiguityMillis int64
}

// merge combines matching identities, requiring every candidate to export graph metrics.
func (s Service) merge(other Service) (Service, bool) {
	if s.Name == "" {
		return other, true
	}
	if s.Name != other.Name || s.Namespace != other.Namespace {
		return Service{}, false
	}
	s.ServiceGraph = s.ServiceGraph && other.ServiceGraph
	return s, true
}

// protocolMetricsEnabled checks the same event-to-instrumentation mapping as the metrics gate.
func protocolMetricsEnabled(selection *instrumentations.InstrumentationSelection, event request.EventType) bool {
	if selection == nil {
		return false
	}
	protocol, ok := event.Instrumentation()
	return !ok || selection.Enabled(protocol)
}
