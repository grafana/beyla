package beyla

import (
	"time"

	"go.opentelemetry.io/obi/pkg/metadata/peer"

	cfgutil "github.com/grafana/beyla/v3/pkg/helpers/config"
)

// PeerMetadataConfig is the v1 configuration for peer metadata exchange.
// OBI accepts these settings only from config v2 and tags peer.MetadataConfig
// out of its v1 loader. The exported fields match that struct so FromOBI and
// AsOBI copy them by name.
type PeerMetadataConfig struct {
	Enabled          bool                  `yaml:"enabled" env:"BEYLA_PEER_METADATA_ENABLED"`
	Mode             peer.Mode             `yaml:"mode" env:"BEYLA_PEER_METADATA_MODE" validate:"omitempty,oneof=peer central"`
	ListenAddress    string                `yaml:"listen_address" env:"BEYLA_PEER_METADATA_LISTEN_ADDRESS"`
	Port             int                   `yaml:"port" env:"BEYLA_PEER_METADATA_PORT"`
	PeerCIDRs        []string              `yaml:"peer_cidrs" env:"BEYLA_PEER_METADATA_PEER_CIDRS" envSeparator:","`
	RefreshInterval  time.Duration         `yaml:"refresh_interval" env:"BEYLA_PEER_METADATA_REFRESH_INTERVAL" validate:"gte=1ms"`
	CallerTTL        time.Duration         `yaml:"caller_ttl" env:"BEYLA_PEER_METADATA_CALLER_TTL" validate:"gte=1ms"`
	CacheTTL         time.Duration         `yaml:"cache_ttl" env:"BEYLA_PEER_METADATA_CACHE_TTL" validate:"gte=1ms"`
	RequestTimeout   time.Duration         `yaml:"request_timeout" env:"BEYLA_PEER_METADATA_REQUEST_TIMEOUT" validate:"gte=1ms"`
	MaxPeers         int                   `yaml:"max_peers" env:"BEYLA_PEER_METADATA_MAX_PEERS" validate:"gt=0"`
	MaxConcurrent    int                   `yaml:"max_concurrent" env:"BEYLA_PEER_METADATA_MAX_CONCURRENT" validate:"gt=0"`
	MaxCallerEntries int                   `yaml:"max_caller_entries" env:"BEYLA_PEER_METADATA_MAX_CALLER_ENTRIES" validate:"gt=0"`
	MaxResponseBytes int                   `yaml:"max_response_bytes" env:"BEYLA_PEER_METADATA_MAX_RESPONSE_BYTES" validate:"gt=0"`
	MaxCacheBytes    int                   `yaml:"max_cache_bytes" env:"BEYLA_PEER_METADATA_MAX_CACHE_BYTES" validate:"gt=0"`
	Token            string                `yaml:"token" env:"BEYLA_PEER_METADATA_TOKEN"`
	TLS              PeerMetadataTLSConfig `yaml:"tls"`
}

// PeerMetadataTLSConfig is the v1 TLS configuration for peer metadata exchange.
type PeerMetadataTLSConfig struct {
	Enabled    bool   `yaml:"enabled" env:"BEYLA_PEER_METADATA_TLS_ENABLED"`
	CertFile   string `yaml:"cert_file" env:"BEYLA_PEER_METADATA_TLS_CERT_FILE"`
	KeyFile    string `yaml:"key_file" env:"BEYLA_PEER_METADATA_TLS_KEY_FILE"`
	CAFile     string `yaml:"ca_file" env:"BEYLA_PEER_METADATA_TLS_CA_FILE"`
	ServerName string `yaml:"server_name" env:"BEYLA_PEER_METADATA_TLS_SERVER_NAME"`
}

// Validate checks the settings with the same rules as peer.MetadataConfig.
func (c PeerMetadataConfig) Validate() error {
	return c.obi().Validate()
}

func (c PeerMetadataConfig) obi() peer.MetadataConfig {
	var dst peer.MetadataConfig
	cfgutil.Convert(&c, &dst, nil)
	return dst
}
