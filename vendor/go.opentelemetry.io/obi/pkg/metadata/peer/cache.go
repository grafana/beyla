// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
)

type cachedPeer struct {
	address   netip.Addr
	lastUsed  time.Time
	lastGood  time.Time
	nextFetch time.Time
	fetchedAt time.Time
	fetching  bool
	failures  int
	size      int
	snapshot  *cachedSnapshot
}

type peerCache struct {
	mu           sync.Mutex
	cfg          MetadataConfig
	peers        *simplelru.LRU[netip.Addr, *cachedPeer]
	bytes        int
	wake         chan struct{}
	refreshBurst int
}

func newPeerCache(cfg MetadataConfig) *peerCache {
	c := &peerCache{
		cfg:  cfg,
		wake: make(chan struct{}, 1),
	}

	c.peers, _ = simplelru.NewLRU(cfg.MaxPeers, func(_ netip.Addr, peer *cachedPeer) {
		c.bytes -= peer.size
	})

	return c
}

// lookup tracks peer activity, schedules newly seen peers, and returns metadata if it is within its TTL.
func (c *peerCache) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	peer, exists := c.peers.Get(address)
	if !exists {
		peer = &cachedPeer{address: address, nextFetch: now}
		c.peers.Add(address, peer)
		c.notify()
	}

	// reject stale metadata
	peer.lastUsed = now
	if peer.snapshot == nil || now.Sub(peer.lastGood) >= c.cfg.CacheTTL {
		return nil, time.Time{}
	}

	return peer.snapshot, peer.fetchedAt
}

// knownCallers reports the requester's cached observations without registering or refreshing it.
func (c *peerCache) knownCallers(address netip.Addr, now time.Time) []Caller {
	c.mu.Lock()
	defer c.mu.Unlock()

	peer, exists := c.peers.Peek(address)
	if !exists || peer.snapshot == nil || now.Sub(peer.lastGood) >= c.cfg.CacheTTL {
		return nil
	}

	age := now.Sub(peer.fetchedAt).Milliseconds()
	if peer.snapshot.ambiguityMillis > age {
		return nil
	}

	cacheRemaining := (c.cfg.CacheTTL - now.Sub(peer.lastGood)).Milliseconds()
	var callers []Caller
	for destination, candidates := range peer.snapshot.callers {
		caller := Caller{Destination: destination}
		for _, candidate := range candidates {
			remaining := min(candidate.RemainingMillis-age, cacheRemaining)
			if remaining > 0 {
				caller.Services = append(caller.Services, CallerService{Service: candidate.Service, RemainingMillis: remaining})
			}
		}
		if len(caller.Services) > 0 {
			callers = append(callers, caller)
		}
	}
	return callers
}

func (c *peerCache) notify() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// due expires inactive peers and orders refreshes and probes without changing LRU recency.
func (c *peerCache) due(now time.Time, limit int) []*cachedPeer {
	c.mu.Lock()
	defer c.mu.Unlock()

	var refreshes, probes []*cachedPeer
	for _, address := range c.peers.Keys() {
		peer, _ := c.peers.Peek(address)
		if now.Sub(peer.lastUsed) >= c.cfg.CacheTTL {
			c.peers.Remove(address)
			continue
		}

		if limit <= 0 || peer.fetching || now.Before(peer.nextFetch) {
			continue
		}

		if peer.snapshot != nil && peer.failures == 0 {
			refreshes = append(refreshes, peer)
		} else {
			probes = append(probes, peer)
		}
	}

	byDeadline := func(a, b *cachedPeer) int { return a.nextFetch.Compare(b.nextFetch) }
	slices.SortStableFunc(refreshes, byDeadline)
	slices.SortStableFunc(probes, byDeadline)
	return c.reserveDue(refreshes, probes, limit)
}

// reserveDue prioritizes responsive peers while keeping discovery probes moving.
func (c *peerCache) reserveDue(refreshes, probes []*cachedPeer, limit int) []*cachedPeer {
	var selected []*cachedPeer
	for len(selected) < limit && len(refreshes)+len(probes) > 0 {
		var peer *cachedPeer
		if len(refreshes) > 0 && (len(probes) == 0 || c.refreshBurst < c.cfg.MaxConcurrent) {
			peer = refreshes[0]
			refreshes = refreshes[1:]
			c.refreshBurst = min(c.refreshBurst+1, c.cfg.MaxConcurrent)
		} else {
			peer = probes[0]
			probes = probes[1:]
			c.refreshBurst = 0
		}
		peer.fetching = true
		selected = append(selected, peer)
	}
	return selected
}

// complete records a fetch result, schedules the next attempt, and enforces the cache byte budget.
func (c *peerCache) complete(peer *cachedPeer, snapshot *cachedSnapshot, size int, started, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	current, exists := c.peers.Peek(peer.address)
	if !exists || current != peer {
		return
	}

	peer.fetching = false

	if snapshot == nil {
		peer.failures = min(peer.failures+1, 16)
		peer.nextFetch = now.Add(jitter(backoff(c.cfg.RefreshInterval, peer.failures)))
		c.notify()
		return
	}

	c.bytes -= peer.size
	peer.snapshot, peer.size = snapshot, size
	peer.lastGood, peer.fetchedAt = now, started
	peer.failures = 0
	peer.nextFetch = now.Add(jitter(c.cfg.RefreshInterval))
	c.bytes += size

	for c.bytes > c.cfg.MaxCacheBytes {
		c.peers.RemoveOldest()
	}

	c.notify()
}

func jitter(interval time.Duration) time.Duration {
	return time.Duration(float64(interval) * (0.9 + rand.Float64()*0.2))
}

// backoff doubles the retry interval per failure, capped at the greater of one minute and the base interval.
func backoff(interval time.Duration, failures int) time.Duration {
	limit := max(time.Minute, interval)

	for range failures {
		if interval >= limit/2 {
			return limit
		}
		interval *= 2
	}

	return min(interval, limit)
}
