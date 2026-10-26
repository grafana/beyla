package beyla

import (
	"time"

	"go.opentelemetry.io/obi/pkg/transform"
)

// NameResolverConfig configures service name resolution, its metadata sources,
// the resolver cache, and cloud discovery scopes.
type NameResolverConfig struct {
	Sources  []transform.Source      `yaml:"sources" env:"OTEL_EBPF_NAME_RESOLVER_SOURCES" envSeparator:","`
	CacheLen int                     `yaml:"cache_len" env:"OTEL_EBPF_NAME_RESOLVER_CACHE_LEN" validate:"gt=0"`
	CacheTTL time.Duration           `yaml:"cache_expiry" env:"OTEL_EBPF_NAME_RESOLVER_CACHE_TTL" validate:"gt=0"`
	GCE      GCENameResolverConfig   `yaml:"gce"`
	Azure    AzureNameResolverConfig `yaml:"azure"`
}

type GCENameResolverConfig struct {
	// Empty project and zone values use the identity detected from GCE metadata.
	ProjectID string `yaml:"project_id" env:"BEYLA_NAME_RESOLVER_GCE_PROJECT_ID"`
	Zone      string `yaml:"zone" env:"BEYLA_NAME_RESOLVER_GCE_ZONE"`
	// Endpoint overrides the Compute API base URL for an emulator or API proxy.
	Endpoint string `yaml:"endpoint" env:"BEYLA_NAME_RESOLVER_GCE_ENDPOINT"`
}

type AzureNameResolverConfig struct {
	// Empty values use the subscription and resource group detected from Azure metadata.
	SubscriptionID string `yaml:"subscription_id" env:"BEYLA_NAME_RESOLVER_AZURE_SUBSCRIPTION_ID"`
	ResourceGroup  string `yaml:"resource_group" env:"BEYLA_NAME_RESOLVER_AZURE_RESOURCE_GROUP"`
}
