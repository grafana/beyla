package beyla

import (
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubeflags"
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

type KubernetesDecorator struct {
	Enable kubeflags.EnableFlag `yaml:"enable" env:"BEYLA_KUBE_METADATA_ENABLE"`

	// ClusterName overrides cluster name. If empty, the NetO11y module will try to retrieve
	// it from the Cloud Provider Metadata (EC2, GCP and Azure), and leave it empty if it fails to.
	// nolint:undoc
	ClusterName string `yaml:"cluster_name" env:"BEYLA_KUBE_CLUSTER_NAME"`

	// KubeconfigPath is optional. If unset, it will look in the usual location.
	KubeconfigPath string `yaml:"kubeconfig_path" env:"KUBECONFIG"`

	InformersSyncTimeout time.Duration `yaml:"informers_sync_timeout" env:"BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT"`

	// InformersResyncPeriod defaults to 30m. Higher values will reduce the load on the Kube API.
	InformersResyncPeriod time.Duration `yaml:"informers_resync_period" env:"BEYLA_KUBE_INFORMERS_RESYNC_PERIOD"`

	// DropExternal will drop, in NetO11y component, any flow where the source or destination
	// IPs are not matched to any kubernetes entity, assuming they are cluster-external
	// nolint:undoc
	DropExternal bool `yaml:"drop_external" env:"BEYLA_NETWORK_DROP_EXTERNAL"`

	// DisableInformers allows selectively disabling some informers. Accepted value is a list
	// that might contain node or service. Disabling any of them
	// will cause metadata to be incomplete but will reduce the load of the Kube API.
	// Pods informer can't be disabled. For that purpose, you should disable the whole
	// kubernetes metadata decoration.
	DisableInformers []string `yaml:"disable_informers" env:"BEYLA_KUBE_DISABLE_INFORMERS"`

	// MetaCacheAddress is the host:port address of the beyla-k8s-cache service instance
	// nolint:undoc
	MetaCacheAddress string `yaml:"meta_cache_address" env:"BEYLA_KUBE_META_CACHE_ADDRESS"`

	// MetaRestrictLocalNode will download only the metadata from the Pods that are located in the same
	// node as the Beyla instance. It will also restrict the Node information to the local node.
	MetaRestrictLocalNode bool `yaml:"meta_restrict_local_node" env:"BEYLA_KUBE_META_RESTRICT_LOCAL_NODE"`

	// MetaSourceLabels allows Beyla overriding the service name and namespace of an application from
	// the given labels.
	// Deprecated: kept for backwards-compatibility with Beyla 1.9
	MetaSourceLabels metaSourceLabels `yaml:"meta_source_labels"`

	// ResourceLabels allows Beyla overriding the OTEL Resource attributes from a map of user-defined labels.
	// nolint:undoc
	ResourceLabels kube.ResourceLabels `yaml:"resource_labels"`

	// ServiceNameTemplate allows to override the service.name with a custom value. Uses the go template language.
	ServiceNameTemplate string `yaml:"service_name_template" env:"BEYLA_SERVICE_NAME_TEMPLATE"`
}

// metasourceLabels mimics OBI's kube.MetaSourceLabels (.obi-src/pkg/components/kube/store.go)
// but keeping BEYLA_ prefixed env vars for backwards compatibility
type metaSourceLabels struct {
	//nolint:undoc
	ServiceName string `yaml:"service_name" env:"BEYLA_KUBE_META_SOURCE_LABEL_SERVICE_NAME"`
	//nolint:undoc
	ServiceNamespace string `yaml:"service_namespace" env:"BEYLA_KUBE_META_SOURCE_LABEL_SERVICE_NAMESPACE"`
}
