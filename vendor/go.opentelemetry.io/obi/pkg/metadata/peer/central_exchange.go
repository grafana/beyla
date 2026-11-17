// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"google.golang.org/grpc"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

var errHostNotPublished = errors.New("no metadata published for the host")

// centralExchange publishes the local store to the central metadata service and looks up remote hosts in it.
type centralExchange struct {
	cfg    MetadataConfig
	hostID string
	store  *localStore
	// addresses are both published as this host's addresses and sent as the requester addresses of lookups.
	addresses []string
	cache     *peerCache
	conn      *grpc.ClientConn
	client    metadatapb.MetadataServiceClient
	closeOnce sync.Once
}

func newCentralExchange(cfg MetadataConfig, hostID string, store *localStore, network network,
	options ...grpc.DialOption,
) (*centralExchange, error) {
	// Hostnames are not unique across hosts, so the service would mix up the metadata of hosts sharing one.
	if !validName(hostID) {
		return nil, errors.New("peer metadata central mode requires a host ID")
	}

	clientTLS, err := clientTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	dialOptions := clientDialOptions(&cfg, clientTLS)
	dialOptions = append(dialOptions, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(cfg.MaxResponseBytes)))
	dialOptions = append(dialOptions, options...)

	conn, err := grpc.NewClient(cfg.Central.Address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("connecting to the metadata service: %w", err)
	}

	return &centralExchange{
		cfg:       cfg,
		hostID:    hostID,
		store:     store,
		addresses: publishedAddresses(network),
		cache:     newPeerCache(cfg),
		conn:      conn,
		client:    metadatapb.NewMetadataServiceClient(conn),
	}, nil
}

// publishedAddresses returns the local addresses that other agents can reach this host through.
func publishedAddresses(network network) []string {
	var addresses []string
	for _, address := range network.addresses {
		if !address.IsLoopback() && network.permits(address) {
			addresses = append(addresses, address.String())
		}
	}

	return addresses
}

func (c *centralExchange) close() {
	c.closeOnce.Do(func() {
		_ = c.conn.Close()
	})
}

func (c *centralExchange) lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time) {
	return c.cache.lookup(address, now)
}

// run periodically publishes local metadata and refreshes remote hosts until cancellation.
func (c *centralExchange) run(ctx context.Context) {
	var workers sync.WaitGroup

	workers.Go(func() {
		c.publishPeriodically(ctx)
	})

	c.createRefresher().run(ctx)
	workers.Wait()
}

// createRefresher returns a refresher that looks up remote hosts in the metadata service.
func (c *centralExchange) createRefresher() *refresher {
	return &refresher{
		cfg:   &c.cfg,
		cache: c.cache,
		fetch: c.fetch,
	}
}

// publishPeriodically publishes the local metadata on start and then every refresh interval.
func (c *centralExchange) publishPeriodically(ctx context.Context) {
	if len(c.addresses) == 0 {
		slog.Warn("no local addresses within peer_cidrs to publish; other agents cannot resolve this host")
		return
	}

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	failing := false
	for {
		err := c.publish(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil && !failing:
			slog.Warn("publishing peer metadata failed, retrying", "address", c.cfg.Central.Address, "error", err)
		case err == nil && failing:
			slog.Info("publishing peer metadata recovered", "address", c.cfg.Central.Address)
		}
		failing = err != nil

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *centralExchange) publish(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	snapshot := c.store.snapshot(allCallers, time.Now())
	_, err := c.client.Publish(withBearerToken(ctx, c.cfg.Token), &metadatapb.PublishRequest{
		HostId:    c.hostID,
		Addresses: c.addresses,
		Snapshot:  snapshotToProto(&snapshot),
	})
	return err
}

func (c *centralExchange) fetch(ctx context.Context, address netip.Addr) (*Snapshot, int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.RequestTimeout)
	defer cancel()

	response, err := c.client.Lookup(withBearerToken(ctx, c.cfg.Token), &metadatapb.LookupRequest{
		Address:            address.String(),
		RequesterAddresses: c.addresses,
	})
	if err != nil {
		return nil, 0, err
	}

	// Unknown hosts are retried with the failure backoff, since they may publish later.
	if response.GetSnapshot() == nil {
		return nil, 0, errHostNotPublished
	}

	return decodeSnapshot(response.GetSnapshot(), c.cfg.CallerTTL)
}
