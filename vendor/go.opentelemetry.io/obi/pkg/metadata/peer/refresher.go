// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// refresher keeps the cached snapshots of active peers fresh, independently of how they are fetched.
type refresher struct {
	cfg   *MetadataConfig
	cache *peerCache
	fetch func(ctx context.Context, address netip.Addr) (*Snapshot, int, error)
	// afterSchedule optionally runs after each scheduling pass, once inactive peers have been evicted.
	afterSchedule func()
}

// run fetches peer snapshots as they become due, with at most MaxConcurrent requests in flight, until cancellation.
func (r *refresher) run(ctx context.Context) {
	var workers sync.WaitGroup

	jobs := make(chan *cachedPeer, r.cfg.MaxConcurrent)
	for range r.cfg.MaxConcurrent {
		workers.Go(func() {
			r.fetchPeers(ctx, jobs)
		})
	}

	r.schedulePeers(ctx, jobs)
	workers.Wait()
}

// fetchPeers downloads queued peer snapshots and records each refresh result in the cache.
func (r *refresher) fetchPeers(ctx context.Context, jobs <-chan *cachedPeer) {
	for {
		select {
		case <-ctx.Done():
			return
		case peer := <-jobs:
			started := time.Now()
			snapshot, size, err := r.fetch(ctx, peer.address)

			var indexed *cachedSnapshot
			if err == nil {
				indexed = indexSnapshot(snapshot)
			} else if ctx.Err() == nil {
				slog.Debug("peer metadata unavailable", "peer", peer.address, "error", err)
			}

			r.cache.complete(peer, indexed, size, started, time.Now())
		}
	}
}

// schedulePeers queues peer refreshes as capacity allows.
func (r *refresher) schedulePeers(ctx context.Context, jobs chan<- *cachedPeer) {
	ticker := time.NewTicker(pollInterval(r.cfg))
	defer ticker.Stop()

	for {
		for _, peer := range r.cache.due(time.Now(), cap(jobs)-len(jobs)) {
			select {
			case jobs <- peer:
			case <-ctx.Done():
				return
			}
		}
		if r.afterSchedule != nil {
			r.afterSchedule()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-r.cache.wake:
		}
	}
}
