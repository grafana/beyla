// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/selection"
)

type localStore struct {
	mu              sync.RWMutex
	hostname        string
	graphEnabled    bool
	metricsPIDs     selection.PIDSelector
	metricProtocols instrumentations.InstrumentationSelection
	callerTTL       time.Duration
	maxCallers      int
	callerCount     int
	ambiguousUntil  time.Time
	services        []Service
	listeners       []Listener
	listenerIndex   map[Endpoint][]Service
	callers         map[Endpoint]map[Service]time.Time
}

// We could map a single Endpoint to Service for the listenerIndex. But multiple
// processes can share a port through SO_REUSEPORT, so we keep track of multiple
// Services per endpoint.
func newStore(hostname string, cfg MetadataConfig) *localStore {
	return &localStore{
		hostname: hostname, callerTTL: cfg.CallerTTL, maxCallers: cfg.MaxCallerEntries,
		metricProtocols: instrumentations.NewInstrumentationSelection([]instrumentations.Instrumentation{instrumentations.InstrumentationALL}),
		listenerIndex:   map[Endpoint][]Service{},
		callers:         map[Endpoint]map[Service]time.Time{},
	}
}

func (s *localStore) serviceFor(attrs svc.Attrs) Service {
	graphEnabled := s.graphEnabled && attrs.Features.ServiceGraph() && attrs.ExportModes.CanExportMetrics()
	if graphEnabled && s.metricsPIDs != nil {
		pid := attrs.DynamicSelectorPID
		if pid == 0 {
			pid = attrs.ProcPID
		}
		graphEnabled = s.metricsPIDs.IncludesPID(pid)
	}
	return Service{Name: attrs.UID.Name, Namespace: attrs.UID.Namespace, ServiceGraph: graphEnabled}
}

func (s *localStore) setInventory(services []Service, listeners []Listener) {
	index := map[Endpoint][]Service{}
	for _, listener := range listeners {
		index[listener.Endpoint] = append(index[listener.Endpoint], listener.Service)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.services = services
	s.listeners = listeners
	s.listenerIndex = index
}

func (s *localStore) observe(destination Endpoint, service Service, now time.Time) {
	if service.Name == "" || destination.Port <= 0 || destination.Port > 65535 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	services := s.callers[destination]
	if _, exists := services[service]; !exists {
		if s.callerCount >= s.maxCallers {
			// A dropped caller must not make a partially observed set look unique.
			s.ambiguousUntil = now.Add(s.callerTTL)
			return
		}

		if services == nil {
			services = map[Service]time.Time{}
			s.callers[destination] = services
		}

		s.callerCount++
	}

	services[service] = now.Add(s.callerTTL)
}

func (s *localStore) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for destination, services := range s.callers {
		for service, expires := range services {
			if !expires.After(now) {
				delete(services, service)
				s.callerCount--
			}
		}

		if len(services) == 0 {
			delete(s.callers, destination)
		}
	}
}

func (s *localStore) snapshot(targets map[string]struct{}, now time.Time) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapshot := Snapshot{
		Version:               ProtocolVersion,
		Hostname:              s.hostname,
		Services:              append([]Service{}, s.services...),
		Listeners:             append([]Listener{}, s.listeners...),
		CallerAmbiguityMillis: remainingMillis(s.ambiguousUntil, now),
	}
	if s.graphEnabled {
		snapshot.MetricProtocols = &s.metricProtocols
	}

	for destination, services := range s.callers {
		if _, ok := targets[destination.IP]; !ok {
			continue
		}

		caller := Caller{Destination: destination}
		for service, expires := range services {
			if remaining := remainingMillis(expires, now); remaining > 0 {
				caller.Services = append(caller.Services, CallerService{
					Service: service, RemainingMillis: remaining,
				})
			}
		}

		if len(caller.Services) > 0 {
			snapshot.Callers = append(snapshot.Callers, caller)
		}
	}
	return snapshot
}

func remainingMillis(expires, now time.Time) int64 {
	return max(int64(0), expires.Sub(now).Milliseconds())
}

func (s *localStore) destinationService(endpoint Endpoint) (Service, listenerMatch) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return listenerService(s.listenerIndex, endpoint, s.hostname)
}

func (s *localStore) callerService(endpoint Endpoint, now time.Time) Service {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fallback := Service{Name: s.hostname}
	if s.ambiguousUntil.After(now) {
		return fallback
	}

	var selected Service
	for service, expires := range s.callers[endpoint] {
		if !expires.After(now) {
			continue
		}

		var matches bool
		selected, matches = selected.merge(service)
		if !matches {
			return fallback
		}
	}

	if selected.Name == "" {
		return fallback
	}

	return selected
}
