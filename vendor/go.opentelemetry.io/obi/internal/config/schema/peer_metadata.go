// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import "go.yaml.in/yaml/v3"

// PeerMetadataMode selects how agents exchange peer metadata.
type PeerMetadataMode string

const (
	// PeerMetadataModePeer exchanges metadata directly between agents.
	PeerMetadataModePeer PeerMetadataMode = "peer"
	// PeerMetadataModeCentral exchanges metadata through a central metadata service.
	PeerMetadataModeCentral PeerMetadataMode = "central"
)

// UnmarshalYAML parses and validates a peer metadata exchange mode.
func (m *PeerMetadataMode) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "mode", m, PeerMetadataModePeer, PeerMetadataModeCentral)
}

type PeerMetadataEnricher struct {
	Enabled              bool                `yaml:"enabled"`
	Mode                 PeerMetadataMode    `yaml:"mode"`
	ListenAddress        string              `yaml:"listen_address"`
	Port                 int                 `yaml:"port"`
	PeerCIDRs            []string            `yaml:"peer_cidrs"`
	RefreshInterval      Duration            `yaml:"refresh_interval"`
	CallerTTL            Duration            `yaml:"caller_ttl"`
	CacheTTL             Duration            `yaml:"cache_ttl"`
	RequestTimeout       Duration            `yaml:"request_timeout"`
	MaxPeers             int                 `yaml:"max_peers"`
	MaxConcurrent        int                 `yaml:"max_concurrent"`
	MaxCallerEntries     int                 `yaml:"max_caller_entries"`
	MaxResponseBytes     int                 `yaml:"max_response_bytes"`
	MaxCacheBytes        int                 `yaml:"max_cache_bytes"`
	Token                string              `yaml:"token"`
	TLS                  PeerMetadataTLS     `yaml:"tls"`
	Central              PeerMetadataCentral `yaml:"central"`
	AdditionalProperties map[string]any      `yaml:",inline"`
}

type PeerMetadataCentral struct {
	Address              string         `yaml:"address"`
	AdditionalProperties map[string]any `yaml:",inline"`
}

type PeerMetadataTLS struct {
	Enabled              bool           `yaml:"enabled"`
	CertFile             string         `yaml:"cert_file"`
	KeyFile              string         `yaml:"key_file"`
	CAFile               string         `yaml:"ca_file"`
	ServerName           string         `yaml:"server_name"`
	AdditionalProperties map[string]any `yaml:",inline"`
}
