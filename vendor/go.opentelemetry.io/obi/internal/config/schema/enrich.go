// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/transform"
)

// Enrich describes standalone metadata enrichment settings.
type Enrich struct {
	Enrichers            Enrichers            `yaml:"enrichers"`
	ServiceName          ServiceName          `yaml:"service_name"`
	Attributes           EnrichmentAttributes `yaml:"attributes"`
	AdditionalProperties map[string]any       `yaml:",inline"`
}

// Enrichers groups metadata enricher settings.
type Enrichers struct {
	Kubernetes           KubernetesEnricher   `yaml:"kubernetes"`
	Cloud                CloudEnricher        `yaml:"cloud"`
	PeerMetadata         PeerMetadataEnricher `yaml:"peer_metadata"`
	AdditionalProperties map[string]any       `yaml:",inline"`
}

// KubernetesMode describes Kubernetes metadata enricher activation.
type KubernetesMode string

const (
	// KubernetesModeAutodetect enables the enricher when Kubernetes is detected.
	KubernetesModeAutodetect KubernetesMode = "autodetect"
	// KubernetesModeEnabled always enables the Kubernetes enricher.
	KubernetesModeEnabled KubernetesMode = "enabled"
	// KubernetesModeDisabled disables the Kubernetes enricher.
	KubernetesModeDisabled KubernetesMode = "disabled"
)

// UnmarshalYAML parses and validates a Kubernetes enricher mode.
func (m *KubernetesMode) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "mode", m, KubernetesModeAutodetect, KubernetesModeEnabled, KubernetesModeDisabled)
}

// KubernetesEnricher describes Kubernetes metadata enrichment settings.
type KubernetesEnricher struct {
	Mode                 KubernetesMode          `yaml:"mode"`
	ClusterName          string                  `yaml:"cluster_name"`
	ServiceNameTemplate  string                  `yaml:"service_name_template"`
	Auth                 KubernetesAuth          `yaml:"auth"`
	Informers            KubernetesInformers     `yaml:"informers"`
	DropExternal         bool                    `yaml:"drop_external"`
	ResourceLabels       ResourceLabels          `yaml:"resource_labels"`
	MetadataCache        KubernetesMetadataCache `yaml:"metadata_cache"`
	AdditionalProperties map[string]any          `yaml:",inline"`
}

// KubernetesAuth describes Kubernetes authentication settings.
type KubernetesAuth struct {
	KubeconfigPath string `yaml:"kubeconfig_path"`
}

// KubernetesInformers describes Kubernetes informer timing and disablement
// settings.
type KubernetesInformers struct {
	InitialSyncTimeout       Duration `yaml:"initial_sync_timeout"`
	ReconnectInitialInterval Duration `yaml:"reconnect_initial_interval"`
	ResyncPeriod             Duration `yaml:"resync_period"`
	Disabled                 []string `yaml:"disabled"`
}

// ResourceLabels maps resource attribute names to Kubernetes label sources.
type ResourceLabels map[string][]string

// KubernetesMetadataCache describes the Kubernetes metadata cache connection
// and source label settings.
type KubernetesMetadataCache struct {
	Address           string                 `yaml:"address"`
	RestrictLocalNode bool                   `yaml:"restrict_local_node"`
	SourceLabels      KubernetesSourceLabels `yaml:"source_labels"`
}

// KubernetesSourceLabels describes metadata labels used as service identity
// sources.
type KubernetesSourceLabels struct {
	ServiceName      string `yaml:"service_name"`
	ServiceNamespace string `yaml:"service_namespace"`
}

// CloudEnricher describes cloud metadata enrichment settings.
type CloudEnricher struct {
	ClusterName          string         `yaml:"cluster_name"`
	Region               string         `yaml:"region"`
	RefreshInterval      Duration       `yaml:"refresh_interval"`
	Route53              Route53        `yaml:"route53"`
	AdditionalProperties map[string]any `yaml:",inline"`
}

// Route53 describes the Route53 hosted zones used for service name resolution.
type Route53 struct {
	RefreshInterval      Duration       `yaml:"refresh_interval"`
	HostedZoneIDs        []string       `yaml:"hosted_zone_ids"`
	AdditionalProperties map[string]any `yaml:",inline"`
}

// ServiceName describes service name resolution settings.
type ServiceName struct {
	UnresolvedHosts      UnresolvedHosts                  `yaml:"unresolved_hosts"`
	Sources              []transform.Source               `yaml:"sources"`
	GCE                  *transform.GCENameResolverConfig `yaml:"gce,omitempty"`
	Azure                AzureServiceName                 `yaml:"azure,omitempty"`
	Cache                Cache                            `yaml:"cache"`
	AdditionalProperties map[string]any                   `yaml:",inline"`
}

// AzureServiceName scopes Uniform scale set discovery to one resource group.
type AzureServiceName struct {
	SubscriptionID       string         `yaml:"subscription_id,omitempty"`
	ResourceGroup        string         `yaml:"resource_group,omitempty"`
	AdditionalProperties map[string]any `yaml:",inline"`
}

// UnresolvedHosts describes names assigned to unresolved hosts.
type UnresolvedHosts struct {
	Names UnresolvedHostNames `yaml:"names"`
}

// UnresolvedHostNames describes default, outgoing, and incoming unresolved host
// names.
type UnresolvedHostNames struct {
	Default  string `yaml:"default"`
	Outgoing string `yaml:"outgoing"`
	Incoming string `yaml:"incoming"`
}

// EnrichmentAttributes describes metadata attributes selected for enrichment.
type EnrichmentAttributes struct {
	Select               attributes.Selection `yaml:"select"`
	ExtraGroupAttributes ExtraGroupAttributes `yaml:"extra_group_attributes"`
	MetadataRetry        MetadataRetry        `yaml:"metadata_retry"`
	AdditionalProperties map[string]any       `yaml:",inline"`
}

// ExtraGroupAttributes maps OBI attribute group names to extra attribute names.
type ExtraGroupAttributes map[string][]attr.Name

// MetadataRetry describes metadata retry timing.
type MetadataRetry struct {
	Timeout       Duration `yaml:"timeout"`
	StartInterval Duration `yaml:"start_interval"`
	MaxInterval   Duration `yaml:"max_interval"`
}
