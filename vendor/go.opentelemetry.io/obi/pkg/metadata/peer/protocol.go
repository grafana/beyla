// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

const (
	ProtocolVersion = 1
	MetadataPath    = "/v1/metadata"
)

type Service struct {
	Name         string `json:"name"`
	Namespace    string `json:"namespace,omitempty"`
	ServiceGraph bool   `json:"service_graph,omitempty"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Listener struct {
	Endpoint Endpoint `json:"endpoint"`
	Service  Service  `json:"service"`
}

type CallerService struct {
	Service         Service `json:"service"`
	RemainingMillis int64   `json:"remaining_ms"`
}

type Caller struct {
	Destination Endpoint        `json:"destination"`
	Services    []CallerService `json:"services"`
}

// Relative lifetimes avoid requiring synchronized clocks between agents.
type Snapshot struct {
	Version               int                                        `json:"version"`
	Hostname              string                                     `json:"hostname"`
	Services              []Service                                  `json:"services"`
	Listeners             []Listener                                 `json:"listeners"`
	Callers               []Caller                                   `json:"callers,omitempty"`
	KnownCallers          []Caller                                   `json:"known_callers,omitempty"`
	MetricProtocols       *instrumentations.InstrumentationSelection `json:"metric_protocols,omitempty"`
	CallerAmbiguityMillis int64                                      `json:"caller_ambiguity_ms,omitempty"`
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
