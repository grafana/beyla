// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// peerExchange serves the local store over HTTP and fetches snapshots directly from each remote agent.
type peerExchange struct {
	cfg       MetadataConfig
	store     *localStore
	network   network
	cache     *peerCache
	client    *http.Client
	server    *http.Server
	listener  net.Listener
	closeOnce sync.Once
}

func newPeerExchange(ctx context.Context, cfg MetadataConfig, store *localStore, network network) (*peerExchange, error) {
	serverTLS, clientTLS, err := tlsConfigs(cfg.TLS)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listening for peer metadata: %w", err)
	}

	if serverTLS != nil {
		listener = tls.NewListener(listener, serverTLS)
	}

	p := &peerExchange{
		cfg:      cfg,
		store:    store,
		network:  network,
		cache:    newPeerCache(cfg),
		client:   newHTTPClient(cfg, clientTLS),
		listener: listener,
	}

	p.server = &http.Server{
		Handler:           metadataHandler(store, cfg, network, p.cache),
		ReadHeaderTimeout: cfg.RequestTimeout,
		ReadTimeout:       cfg.RequestTimeout,
		WriteTimeout:      cfg.RequestTimeout,
		IdleTimeout:       3 * cfg.RefreshInterval,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	return p, nil
}

func (p *peerExchange) close() {
	p.closeOnce.Do(func() {
		_ = p.server.Close()
		_ = p.listener.Close()
		p.client.CloseIdleConnections()
	})
}

func (p *peerExchange) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	return p.cache.lookup(address, now)
}

// run serves local metadata and refreshes peers until cancellation.
func (p *peerExchange) run(ctx context.Context) {
	var workers sync.WaitGroup

	workers.Go(func() {
		if err := p.server.Serve(p.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && ctx.Err() == nil {
			slog.Error("peer metadata server stopped", "error", err)
		}
	})

	jobs := make(chan *cachedPeer, p.cfg.MaxConcurrent)
	for range p.cfg.MaxConcurrent {
		workers.Go(func() {
			p.fetchPeers(ctx, jobs)
		})
	}

	p.schedulePeers(ctx, jobs)
	workers.Wait()
}

// fetchPeers downloads queued peer snapshots and records each refresh result in the cache.
func (p *peerExchange) fetchPeers(ctx context.Context, jobs <-chan *cachedPeer) {
	for {
		select {
		case <-ctx.Done():
			return
		case peer := <-jobs:
			started := time.Now()
			snapshot, size, err := fetchSnapshot(ctx, p.client, p.cfg, peer.address)

			var indexed *cachedSnapshot
			if err == nil {
				indexed = indexSnapshot(snapshot)
			} else if ctx.Err() == nil {
				slog.Debug("peer metadata unavailable", "peer", peer.address, "error", err)
			}

			p.cache.complete(peer, indexed, size, started, time.Now())
		}
	}
}

// schedulePeers queues peer refreshes as capacity allows.
func (p *peerExchange) schedulePeers(ctx context.Context, jobs chan<- *cachedPeer) {
	ticker := time.NewTicker(pollInterval(&p.cfg))
	defer ticker.Stop()

	for {
		for _, peer := range p.cache.due(time.Now(), cap(jobs)-len(jobs)) {
			select {
			case jobs <- peer:
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-p.cache.wake:
		}
	}
}
