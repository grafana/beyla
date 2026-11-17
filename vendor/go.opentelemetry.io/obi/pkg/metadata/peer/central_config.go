// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
	"gopkg.in/yaml.v3"

	"go.opentelemetry.io/obi/pkg/config"
)

const DefaultCentralPort = 8999

// CentralServerConfig configures the central metadata service.
type CentralServerConfig struct {
	// LogLevel can be one of: debug, info, warn, error
	LogLevel      string `yaml:"log_level" env:"OTEL_EBPF_METADATA_SERVICE_LOG_LEVEL"`
	ListenAddress string `yaml:"listen_address" env:"OTEL_EBPF_METADATA_SERVICE_LISTEN_ADDRESS"`
	Port          int    `yaml:"port" env:"OTEL_EBPF_METADATA_SERVICE_PORT"`
	// PeerCIDRs restricts the host addresses agents can publish. Empty allows the private address blocks.
	PeerCIDRs []string `yaml:"peer_cidrs" env:"OTEL_EBPF_METADATA_SERVICE_PEER_CIDRS"`
	// HostTTL removes hosts that stop publishing.
	HostTTL         time.Duration     `yaml:"host_ttl" env:"OTEL_EBPF_METADATA_SERVICE_HOST_TTL" validate:"gte=1ms"`
	CallerTTL       time.Duration     `yaml:"caller_ttl" env:"OTEL_EBPF_METADATA_SERVICE_CALLER_TTL" validate:"gte=1ms"`
	MaxHosts        int               `yaml:"max_hosts" env:"OTEL_EBPF_METADATA_SERVICE_MAX_HOSTS" validate:"gt=0"`
	MaxMessageBytes int               `yaml:"max_message_bytes" env:"OTEL_EBPF_METADATA_SERVICE_MAX_MESSAGE_BYTES" validate:"gt=0"`
	Token           string            `yaml:"token" env:"OTEL_EBPF_METADATA_SERVICE_TOKEN"`
	TLS             MetadataTLSConfig `yaml:"tls"`
}

func DefaultCentralServerConfig() CentralServerConfig {
	return CentralServerConfig{
		LogLevel:        "info",
		Port:            DefaultCentralPort,
		HostTTL:         time.Minute,
		CallerTTL:       time.Minute,
		MaxHosts:        4096,
		MaxMessageBytes: 1 << 20,
	}
}

// LoadCentralServerConfig applies, by increasing priority, the defaults, the YAML file (nillable) and the environment.
func LoadCentralServerConfig(file io.Reader) (CentralServerConfig, error) {
	cfg := DefaultCentralServerConfig()
	if file != nil {
		data, err := io.ReadAll(file)
		if err != nil {
			return cfg, fmt.Errorf("reading YAML configuration: %w", err)
		}

		if err := yaml.Unmarshal(config.ReplaceEnv(data), &cfg); err != nil {
			return cfg, fmt.Errorf("parsing YAML configuration: %w", err)
		}
	}

	if err := env.Parse(&cfg); err != nil {
		return cfg, fmt.Errorf("reading env vars: %w", err)
	}

	return cfg, cfg.Validate()
}

func (c *CentralServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("metadata service port must be between 1 and 65535")
	}

	if c.ListenAddress != "" {
		if _, err := netip.ParseAddr(c.ListenAddress); err != nil {
			return fmt.Errorf("metadata service listen_address: %w", err)
		}
	}

	for _, cidr := range c.PeerCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("metadata service peer_cidrs: %w", err)
		}
	}

	if err := configValidator.Struct(c); err != nil {
		return fmt.Errorf("metadata service: %w", err)
	}

	if strings.ContainsAny(c.Token, "\r\n") {
		return errors.New("metadata service token must not contain newlines")
	}

	if c.Token != "" && !c.TLS.Enabled {
		return errors.New("metadata service token requires TLS")
	}

	if c.TLS.Enabled && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return errors.New("metadata service TLS requires cert_file and key_file")
	}

	return nil
}

// publishedNetwork allows the configured CIDRs, or every private block when none are configured.
func (c *CentralServerConfig) publishedNetwork() (network, error) {
	if len(c.PeerCIDRs) == 0 {
		return network{allowed: privateBlocks}, nil
	}

	return makeNetwork(nil, c.PeerCIDRs)
}
