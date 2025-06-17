package beyla

import (
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
)

// structs in this file mimic some structs in from OBI, replacing OTEL_EBPF_*
// by BEYLA_* for backwards compatibility

// mimic imetrics.Config in .obi-src/pkg/imetrics/imetrics.go
type internalMetricsConfig struct {
	Prometheus internalPromConfig               `yaml:"prometheus,omitempty"`
	Exporter   imetrics.InternalMetricsExporter `yaml:"exporter,omitempty" env:"BEYLA_INTERNAL_METRICS_EXPORTER"`
}

type internalPromConfig struct {
	Port int    `yaml:"port,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH"`
}

type nameResolverConfig struct {
	// Sources for name resolving. Accepted values: dns, k8s
	// nolint:undoc
	Sources []string `yaml:"sources" env:"BEYLA_NAME_RESOLVER_SOURCES" envSeparator:"," envDefault:"k8s"`
	// CacheLen specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	// nolint:undoc
	CacheLen int `yaml:"cache_len" env:"BEYLA_NAME_RESOLVER_CACHE_LEN"`
	// CacheTTL specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	// nolint:undoc
	CacheTTL time.Duration `yaml:"cache_expiry" env:"BEYLA_NAME_RESOLVER_CACHE_TTL"`
}
