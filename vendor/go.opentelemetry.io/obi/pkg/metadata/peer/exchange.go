// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// exchange shares the local store with other agents and supplies metadata about remote hosts.
type exchange interface {
	// run shares local metadata and refreshes remote metadata until cancellation.
	run(ctx context.Context)

	// lookup returns fresh metadata for a remote host and the time it was fetched,
	// or nil when it is unavailable. Looking up a host registers interest in it,
	// so implementations only retrieve metadata for hosts seen in spans.
	lookup(address netip.Addr, now time.Time) (*cachedSnapshot, time.Time)

	close()
}

func newExchange(cfg MetadataConfig, hostID string, store *localStore, network network) (exchange, error) {
	switch cfg.Mode {
	case ModePeer:
		return newPeerExchange(cfg, store, network)
	case ModeCentral:
		return newCentralExchange(cfg, hostID, store, network)
	default:
		return nil, errors.New("unknown peer metadata mode: " + string(cfg.Mode))
	}
}
