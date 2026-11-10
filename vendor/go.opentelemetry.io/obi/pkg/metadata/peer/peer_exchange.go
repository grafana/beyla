// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

// peerExchange serves the local store over gRPC and fetches snapshots directly from each remote agent.
type peerExchange struct {
	metadatapb.UnimplementedPeerMetadataServiceServer

	cfg       MetadataConfig
	store     *localStore
	network   network
	cache     *peerCache
	clients   *peerClients
	server    *grpc.Server
	listener  net.Listener
	closeOnce sync.Once
}

func newPeerExchange(cfg MetadataConfig, store *localStore, network network) (*peerExchange, error) {
	serverTLS, err := serverTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	clientTLS, err := clientTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	listener, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, fmt.Errorf("listening for peer metadata: %w", err)
	}

	p := &peerExchange{
		cfg:      cfg,
		store:    store,
		network:  network,
		cache:    newPeerCache(cfg),
		clients:  newPeerClients(&cfg, clientTLS),
		server:   grpc.NewServer(peerServerOptions(&cfg, serverTLS)...),
		listener: listener,
	}

	metadatapb.RegisterPeerMetadataServiceServer(p.server, p)
	return p, nil
}

func (p *peerExchange) close() {
	p.closeOnce.Do(func() {
		p.server.Stop()
		_ = p.listener.Close()
		p.clients.close()
	})
}

func (p *peerExchange) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	return p.cache.lookup(address, now)
}

// GetSnapshot serves the local metadata, limiting caller observations to the requester's source address.
func (p *peerExchange) GetSnapshot(ctx context.Context, _ *metadatapb.GetSnapshotRequest) (*metadatapb.Snapshot, error) {
	requester, ok := requesterAddress(ctx)
	if !ok || !p.network.permits(requester) {
		return nil, status.Error(codes.PermissionDenied, "peer address is not permitted")
	}

	now := time.Now()
	snapshot := p.store.snapshot(callersTo(requester.String()), now)
	snapshot.KnownCallers = p.cache.knownCallers(requester, now)
	return snapshotToProto(&snapshot), nil
}

// run serves local metadata and refreshes peers until cancellation.
func (p *peerExchange) run(ctx context.Context) {
	var workers sync.WaitGroup

	workers.Go(func() {
		if err := p.server.Serve(p.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) && ctx.Err() == nil {
			slog.Error("peer metadata server stopped", "error", err)
		}
	})

	p.createRefresher().run(ctx)
	workers.Wait()
}

// createRefresher returns a refresher that fetches snapshots directly from each peer, and closes the connections
// to evicted peers.
func (p *peerExchange) createRefresher() *refresher {
	return &refresher{
		cfg:           &p.cfg,
		cache:         p.cache,
		fetch:         p.fetch,
		afterSchedule: func() { p.clients.retain(p.cache.contains) },
	}
}

func (p *peerExchange) fetch(ctx context.Context, address netip.Addr) (*Snapshot, int, error) {
	client, err := p.clients.get(address)
	if err != nil {
		return nil, 0, err
	}

	return fetchSnapshot(ctx, client, &p.cfg)
}
