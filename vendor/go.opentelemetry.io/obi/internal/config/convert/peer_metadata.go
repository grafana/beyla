// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"fmt"

	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/obi"
)

func applyV2PeerMetadata(cfg *obi.Config, enrich *schema.Enrich, complete bool) error {
	if enrich == nil {
		return nil
	}

	src := enrich.Enrichers.PeerMetadata
	cfg.PeerMetadata = peer.MetadataConfig{
		Enabled:          src.Enabled,
		ListenAddress:    src.ListenAddress,
		Port:             src.Port,
		PeerCIDRs:        cloneStrings(src.PeerCIDRs),
		RefreshInterval:  src.RefreshInterval.TimeDuration(),
		CallerTTL:        src.CallerTTL.TimeDuration(),
		CacheTTL:         src.CacheTTL.TimeDuration(),
		RequestTimeout:   src.RequestTimeout.TimeDuration(),
		MaxPeers:         src.MaxPeers,
		MaxConcurrent:    src.MaxConcurrent,
		MaxCallerEntries: src.MaxCallerEntries,
		MaxResponseBytes: src.MaxResponseBytes,
		MaxCacheBytes:    src.MaxCacheBytes,
		Token:            src.Token,
		TLS: peer.MetadataTLSConfig{
			Enabled:    src.TLS.Enabled,
			CertFile:   src.TLS.CertFile,
			KeyFile:    src.TLS.KeyFile,
			CAFile:     src.TLS.CAFile,
			ServerName: src.TLS.ServerName,
		},
		// Config v2 does not expose the exchange mode yet, so the runtime default is kept.
		Mode: cfg.PeerMetadata.Mode,
	}

	if !complete {
		cfg.PeerMetadata = cfg.PeerMetadata.WithDefaults()
	}

	if err := cfg.PeerMetadata.Validate(); err != nil {
		return fmt.Errorf("enrich.enrichers.peer_metadata: %w", err)
	}

	return nil
}

func peerMetadataEnrichment(cfg peer.MetadataConfig) schema.PeerMetadataEnricher {
	cfg = cfg.WithDefaults()
	return schema.PeerMetadataEnricher{
		Enabled:          cfg.Enabled,
		ListenAddress:    cfg.ListenAddress,
		Port:             cfg.Port,
		PeerCIDRs:        cloneStrings(cfg.PeerCIDRs),
		RefreshInterval:  schema.Duration(cfg.RefreshInterval),
		CallerTTL:        schema.Duration(cfg.CallerTTL),
		CacheTTL:         schema.Duration(cfg.CacheTTL),
		RequestTimeout:   schema.Duration(cfg.RequestTimeout),
		MaxPeers:         cfg.MaxPeers,
		MaxConcurrent:    cfg.MaxConcurrent,
		MaxCallerEntries: cfg.MaxCallerEntries,
		MaxResponseBytes: cfg.MaxResponseBytes,
		MaxCacheBytes:    cfg.MaxCacheBytes,
		Token:            cfg.Token,
		TLS: schema.PeerMetadataTLS{
			Enabled:    cfg.TLS.Enabled,
			CertFile:   cfg.TLS.CertFile,
			KeyFile:    cfg.TLS.KeyFile,
			CAFile:     cfg.TLS.CAFile,
			ServerName: cfg.TLS.ServerName,
		},
	}
}
