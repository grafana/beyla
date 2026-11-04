// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

type PeerMetadataEnricher struct {
	Enabled              bool            `yaml:"enabled"`
	ListenAddress        string          `yaml:"listen_address"`
	Port                 int             `yaml:"port"`
	PeerCIDRs            []string        `yaml:"peer_cidrs"`
	RefreshInterval      Duration        `yaml:"refresh_interval"`
	CallerTTL            Duration        `yaml:"caller_ttl"`
	CacheTTL             Duration        `yaml:"cache_ttl"`
	RequestTimeout       Duration        `yaml:"request_timeout"`
	MaxPeers             int             `yaml:"max_peers"`
	MaxConcurrent        int             `yaml:"max_concurrent"`
	MaxCallerEntries     int             `yaml:"max_caller_entries"`
	MaxResponseBytes     int             `yaml:"max_response_bytes"`
	MaxCacheBytes        int             `yaml:"max_cache_bytes"`
	Token                string          `yaml:"token"`
	TLS                  PeerMetadataTLS `yaml:"tls"`
	AdditionalProperties map[string]any  `yaml:",inline"`
}

type PeerMetadataTLS struct {
	Enabled              bool           `yaml:"enabled"`
	CertFile             string         `yaml:"cert_file"`
	KeyFile              string         `yaml:"key_file"`
	CAFile               string         `yaml:"ca_file"`
	ServerName           string         `yaml:"server_name"`
	AdditionalProperties map[string]any `yaml:",inline"`
}
