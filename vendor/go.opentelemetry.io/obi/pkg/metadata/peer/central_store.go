// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

var errTooManyHosts = errors.New("central metadata host limit reached")

type centralHost struct {
	addresses []netip.Addr
	// snapshot holds no callers, which are indexed by destination address so lookups only visit the requester's.
	snapshot  Snapshot
	callers   map[netip.Addr][]Caller
	published time.Time
	// known holds the callers returned to this host by looked up address, to acknowledge them to the host at that address.
	known map[netip.Addr]knownCallers
}

// knownCallers are the callers of a looked up host that the requesting host has cached, aged to the lookup time.
type knownCallers struct {
	callers         []Caller
	ambiguityMillis int64
	recorded        time.Time
	expires         time.Time
}

func newKnownCallers(snapshot *Snapshot, now time.Time) knownCallers {
	var remaining int64
	for _, caller := range snapshot.Callers {
		for _, service := range caller.Services {
			remaining = max(remaining, service.RemainingMillis)
		}
	}

	return knownCallers{
		callers:         snapshot.Callers,
		ambiguityMillis: snapshot.CallerAmbiguityMillis,
		recorded:        now,
		expires:         now.Add(time.Duration(remaining) * time.Millisecond),
	}
}

// appendTo appends the unexpired callers, omitting them all while the requester saw them as ambiguous,
// as the requester itself does when resolving them.
func (k knownCallers) appendTo(dst []Caller, now time.Time) []Caller {
	age := now.Sub(k.recorded).Milliseconds()
	if k.ambiguityMillis > age {
		return dst
	}

	return appendAgedCallers(dst, k.callers, age)
}

// centralStore keeps the latest snapshot published by each host, indexed by the addresses it is reachable at.
// Hosts are keyed by host ID, since distinct hosts may share a hostname.
type centralStore struct {
	mu        sync.RWMutex
	ttl       time.Duration
	maxHosts  int
	hosts     map[string]*centralHost
	addresses map[netip.Addr]string
}

func newCentralStore(ttl time.Duration, maxHosts int) *centralStore {
	return &centralStore{
		ttl:       ttl,
		maxHosts:  maxHosts,
		hosts:     map[string]*centralHost{},
		addresses: map[netip.Addr]string{},
	}
}

// publish replaces the host snapshot. An address claimed by another host moves to the latest publishing host.
func (s *centralStore) publish(hostID string, addresses []netip.Addr, snapshot Snapshot, now time.Time) error {
	callers := indexCallers(snapshot.Callers)
	snapshot.Callers = nil

	s.mu.Lock()
	defer s.mu.Unlock()

	previous, exists := s.hosts[hostID]
	if !exists && len(s.hosts) >= s.maxHosts {
		return errTooManyHosts
	}

	known := map[netip.Addr]knownCallers{}
	if exists {
		s.releaseAddresses(hostID, previous.addresses)
		known = previous.known
	}

	for _, address := range addresses {
		s.addresses[address] = hostID
	}
	s.hosts[hostID] = &centralHost{addresses: addresses, snapshot: snapshot, callers: callers, known: known, published: now}
	return nil
}

// indexCallers groups callers by destination address. Destinations must already be normalized by validateSnapshot.
func indexCallers(callers []Caller) map[netip.Addr][]Caller {
	index := make(map[netip.Addr][]Caller, len(callers))
	for _, caller := range callers {
		destination, err := netip.ParseAddr(caller.Destination.IP)
		if err != nil {
			continue
		}

		index[destination] = append(index[destination], caller)
	}

	return index
}

// lookup returns the snapshot published for an address, aged to now and with callers limited to the requester.
// Known callers acknowledge the requester's callers that the looked up host received in its own lookups.
func (s *centralStore) lookup(address netip.Addr, requester []netip.Addr, now time.Time) (*Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	host, exists := s.hosts[s.addresses[address]]
	if !exists || now.Sub(host.published) >= s.ttl {
		return nil, false
	}

	age := now.Sub(host.published).Milliseconds()
	snapshot := Snapshot{
		Hostname:              host.snapshot.Hostname,
		Services:              slices.Clone(host.snapshot.Services),
		Listeners:             slices.Clone(host.snapshot.Listeners),
		MetricProtocols:       host.snapshot.MetricProtocols,
		CallerAmbiguityMillis: max(0, host.snapshot.CallerAmbiguityMillis-age),
	}

	for _, address := range requester {
		snapshot.Callers = appendAgedCallers(snapshot.Callers, host.callers[address], age)
		snapshot.KnownCallers = host.known[address].appendTo(snapshot.KnownCallers, now)
	}

	s.recordKnownCallers(address, requester, &snapshot, now)
	return &snapshot, true
}

// recordKnownCallers remembers the callers returned to the requesting host, which caches them to resolve its callers.
func (s *centralStore) recordKnownCallers(address netip.Addr, requester []netip.Addr, snapshot *Snapshot, now time.Time) {
	for _, requesterAddress := range requester {
		host, exists := s.hosts[s.addresses[requesterAddress]]
		if !exists {
			continue
		}

		if len(snapshot.Callers) == 0 {
			delete(host.known, address)
			continue
		}

		host.known[address] = newKnownCallers(snapshot, now)
	}
}

// appendAgedCallers appends the callers with their remaining lifetimes reduced by age, dropping expired services.
func appendAgedCallers(dst, callers []Caller, age int64) []Caller {
	for _, caller := range callers {
		aged := Caller{Destination: caller.Destination}
		for _, service := range caller.Services {
			if remaining := service.RemainingMillis - age; remaining > 0 {
				aged.Services = append(aged.Services, CallerService{Service: service.Service, RemainingMillis: remaining})
			}
		}

		if len(aged.Services) > 0 {
			dst = append(dst, aged)
		}
	}

	return dst
}

// expire removes hosts that have not published within the TTL, and known callers whose lifetimes ended.
func (s *centralStore) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for hostID, host := range s.hosts {
		if now.Sub(host.published) >= s.ttl {
			s.releaseAddresses(hostID, host.addresses)
			delete(s.hosts, hostID)
			continue
		}

		for address, known := range host.known {
			if !known.expires.After(now) {
				delete(host.known, address)
			}
		}
	}
}

// releaseAddresses removes the host's address mappings, keeping those already claimed by another host.
func (s *centralStore) releaseAddresses(hostID string, addresses []netip.Addr) {
	for _, address := range addresses {
		if s.addresses[address] == hostID {
			delete(s.addresses, address)
		}
	}
}
