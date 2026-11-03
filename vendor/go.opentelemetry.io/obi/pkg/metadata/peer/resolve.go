// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"net/netip"
	"time"

	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

type cachedSnapshot struct {
	hostname        string
	listeners       map[Endpoint][]Service
	callers         map[Endpoint][]CallerService
	knownCallers    map[Endpoint][]CallerService
	ambiguityMillis int64
	metricProtocols *instrumentations.InstrumentationSelection
}

// indexSnapshot indexes listeners and caller observations by endpoint for cached lookups.
func indexSnapshot(snapshot *Snapshot) *cachedSnapshot {
	indexed := &cachedSnapshot{
		hostname:        snapshot.Hostname,
		ambiguityMillis: snapshot.CallerAmbiguityMillis,
		metricProtocols: snapshot.MetricProtocols,
		listeners:       make(map[Endpoint][]Service),
		callers:         make(map[Endpoint][]CallerService),
		knownCallers:    make(map[Endpoint][]CallerService),
	}

	for _, listener := range snapshot.Listeners {
		indexed.listeners[listener.Endpoint] = append(indexed.listeners[listener.Endpoint], listener.Service)
	}

	for _, caller := range snapshot.Callers {
		indexed.callers[caller.Destination] = append(indexed.callers[caller.Destination], caller.Services...)
	}

	for _, caller := range snapshot.KnownCallers {
		indexed.knownCallers[caller.Destination] = append(indexed.knownCallers[caller.Destination], caller.Services...)
	}

	return indexed
}

type listenerMatch uint8

const (
	listenerMissing listenerMatch = iota
	listenerUnique
	listenerAmbiguous
)

// listenerService distinguishes missing, unique, and ambiguous listeners, falling back to the hostname.
func listenerService(index map[Endpoint][]Service, endpoint Endpoint, hostname string) (Service, listenerMatch) {
	fallback := Service{Name: hostname}
	var selected Service
	address, _ := netip.ParseAddr(endpoint.IP)

	for _, ip := range [...]string{endpoint.IP, "0.0.0.0", "::"} {
		if ip == "0.0.0.0" && address.Is6() {
			continue
		}
		if ip == "::" && address.Is4() && selected.Name != "" {
			continue
		}

		for _, service := range index[Endpoint{IP: ip, Port: endpoint.Port}] {
			var matches bool
			selected, matches = selected.merge(service)
			if !matches {
				return fallback, listenerAmbiguous
			}
		}
	}

	if selected.Name == "" {
		return fallback, listenerMissing
	}

	return selected, listenerUnique
}

// destinationService resolves a destination from the cached listener inventory.
func (s *cachedSnapshot) destinationService(endpoint Endpoint) (Service, listenerMatch) {
	return listenerService(s.listeners, endpoint, s.hostname)
}

// callerService selects a unique unexpired caller, falling back to the hostname when unresolved or ambiguous.
func (s *cachedSnapshot) callerService(endpoint Endpoint, age time.Duration) Service {
	fallback := Service{Name: s.hostname}

	if s.ambiguityMillis > age.Milliseconds() {
		return fallback
	}

	selected := uniqueCaller(s.callers[endpoint], age)
	if selected.Name == "" {
		return fallback
	}

	return selected
}

// knowsCaller checks whether the peer can still resolve this caller at the destination.
func (s *cachedSnapshot) knowsCaller(endpoint Endpoint, caller Service, age time.Duration) bool {
	known := uniqueCaller(s.knownCallers[endpoint], age)
	return caller.Name != "" && known.Name == caller.Name && known.Namespace == caller.Namespace
}

// uniqueCaller selects a single unexpired identity, returning none when ambiguous.
func uniqueCaller(candidates []CallerService, age time.Duration) Service {
	var selected Service
	for _, candidate := range candidates {
		if candidate.RemainingMillis <= age.Milliseconds() {
			continue
		}

		var matches bool
		selected, matches = selected.merge(candidate.Service)
		if !matches {
			return Service{}
		}
	}

	return selected
}
