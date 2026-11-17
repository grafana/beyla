// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"errors"
	"strings"
	"time"
)

// CloudMetadataConfig configures overrides for detected cloud metadata.
type CloudMetadataConfig struct {
	// DetectionEnabled controls startup cloud metadata detection through Config v2.
	DetectionEnabled bool `yaml:"-" env:"-"`
	// ClusterName overrides automatic cluster detection.
	ClusterName string `yaml:"cluster_name" env:"OTEL_EBPF_CLUSTER_NAME"`
	// Region overrides automatic region detection.
	Region string `yaml:"region" env:"OTEL_EBPF_CLOUD_REGION"`
	// RefreshInterval controls how often the cloud metadata inventory is refreshed.
	RefreshInterval time.Duration `yaml:"refresh_interval" env:"OTEL_EBPF_CLOUD_META_REFRESH_INTERVAL" validate:"gt=0"`

	// Route53 provides configuration for Route53 metadata extraction
	Route53 Route53MetadataConfig `yaml:"route53"`
}

// Route53MetadataConfig maps A/AAAA records to fully qualified names.
// Aliases, CNAMEs, and wildcard records are excluded. ECS names take precedence.
type Route53MetadataConfig struct {
	// RefreshInterval controls Route53 polling independently of other cloud sources.
	RefreshInterval time.Duration `yaml:"refresh_interval" env:"OTEL_EBPF_NAME_RESOLVER_ROUTE53_REFRESH_INTERVAL" validate:"gt=0"`
	// HostedZoneIDs optionally restricts the discovered zones. Discovery includes account public zones and private zones associated with the detected VPC. Explicit IDs retain the same VPC and address filters.
	HostedZoneIDs []string `yaml:"hosted_zone_ids" env:"OTEL_EBPF_NAME_RESOLVER_ROUTE53_HOSTED_ZONE_IDS" envSeparator:","`
}

// Validate checks settings required when the Route53 source is enabled.
func (c Route53MetadataConfig) Validate() error {
	if c.RefreshInterval <= 0 {
		return errors.New("enrich.enrichers.cloud.route53.refresh_interval must be greater than zero")
	}
	for _, id := range c.HostedZoneIDs {
		if strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(id), "/hostedzone/")) == "" {
			return errors.New("enrich.enrichers.cloud.route53.hosted_zone_ids must not contain blank IDs")
		}
	}
	return nil
}
