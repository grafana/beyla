// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"

	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

// CaptureNetwork groups network flow capture and network stats settings.
type CaptureNetwork struct {
	Capture NetworkCapture `yaml:"capture"`
	Stats   NetworkStats   `yaml:"stats"`
}

// NetworkSource describes the eBPF source used for network events.
type NetworkSource string

const (
	// NetworkSourceTC captures traffic with tc.
	NetworkSourceTC NetworkSource = "tc"
	// NetworkSourceSocketFilter captures traffic with socket filters.
	NetworkSourceSocketFilter NetworkSource = "socket_filter"
)

// UnmarshalYAML parses and validates a network capture source.
func (s *NetworkSource) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "source", s, NetworkSourceTC, NetworkSourceSocketFilter)
}

// NetworkCapture describes network flow capture settings.
type NetworkCapture struct {
	Enabled              bool               `yaml:"enabled"`
	Source               NetworkSource      `yaml:"source"`
	BufferSize           uint32             `yaml:"buffer_size"`
	EndpointIdentity     EndpointIdentity   `yaml:"endpoint_identity"`
	Selection            NetworkSelection   `yaml:"selection"`
	Filters              SignalFilters      `yaml:"filters"`
	FlowLifecycle        FlowLifecycle      `yaml:"flow_lifecycle"`
	InterfaceDiscovery   InterfaceDiscovery `yaml:"interface_discovery"`
	Enrichment           NetworkEnrichment  `yaml:"enrichment"`
	Diagnostics          FlowDiagnostics    `yaml:"diagnostics"`
	AdditionalProperties map[string]any     `yaml:",inline"`
}

// AgentIPFamily describes the IP address family used for the agent identity.
type AgentIPFamily string

const (
	// AgentIPFamilyAny allows either IPv4 or IPv6.
	AgentIPFamilyAny AgentIPFamily = "any"
	// AgentIPFamilyIPv4 selects IPv4 addresses.
	AgentIPFamilyIPv4 AgentIPFamily = "ipv4"
	// AgentIPFamilyIPv6 selects IPv6 addresses.
	AgentIPFamilyIPv6 AgentIPFamily = "ipv6"
)

// UnmarshalYAML parses and validates an agent IP family.
func (f *AgentIPFamily) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "agent_ip_family", f, AgentIPFamilyAny, AgentIPFamilyIPv4, AgentIPFamilyIPv6)
}

// AgentIPInterface describes how the agent selects an interface for endpoint
// identity.
type AgentIPInterface string

const (
	// AgentIPInterfaceExternal selects an external interface.
	AgentIPInterfaceExternal AgentIPInterface = "external"
	// AgentIPInterfaceLocal selects a local interface.
	AgentIPInterfaceLocal AgentIPInterface = "local"
)

// UnmarshalYAML parses and validates an agent IP interface selector.
func (i *AgentIPInterface) UnmarshalYAML(value *yaml.Node) error {
	if value.Tag == "!!null" {
		*i = ""
		return nil
	}
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("agent_ip_interface must be a scalar, got %v", value.Kind)
	}
	candidate := AgentIPInterface(value.Value)
	switch {
	case candidate == AgentIPInterfaceExternal, candidate == AgentIPInterfaceLocal:
		*i = candidate
		return nil
	case strings.HasPrefix(value.Value, "name:") && strings.TrimPrefix(value.Value, "name:") != "":
		*i = candidate
		return nil
	default:
		return fmt.Errorf("invalid agent_ip_interface %q", value.Value)
	}
}

// EndpointIdentity describes how the local agent endpoint identity is resolved.
type EndpointIdentity struct {
	AgentIP          string           `yaml:"agent_ip"`
	AgentIPInterface AgentIPInterface `yaml:"agent_ip_interface"`
	AgentIPFamily    AgentIPFamily    `yaml:"agent_ip_family"`
}

// NetworkDirection describes the network traffic direction selected for
// capture.
type NetworkDirection string

const (
	// NetworkDirectionIngress selects ingress traffic.
	NetworkDirectionIngress NetworkDirection = "ingress"
	// NetworkDirectionEgress selects egress traffic.
	NetworkDirectionEgress NetworkDirection = "egress"
	// NetworkDirectionBoth selects ingress and egress traffic.
	NetworkDirectionBoth NetworkDirection = "both"
)

// UnmarshalYAML parses and validates a network direction.
func (d *NetworkDirection) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "direction", d, NetworkDirectionIngress, NetworkDirectionEgress, NetworkDirectionBoth)
}

// NetworkSelection describes which network traffic is selected for capture.
type NetworkSelection struct {
	Interfaces IncludeExclude   `yaml:"interfaces"`
	Protocols  IncludeExclude   `yaml:"protocols"`
	Direction  NetworkDirection `yaml:"direction"`
	CIDRs      CIDRDefinitions  `yaml:"cidrs"`
}

// CIDRDefinition describes a CIDR range and its optional display name.
type CIDRDefinition struct {
	CIDR string `yaml:"cidr"`
	Name string `yaml:"name"`
}

// CIDRDefinitions lists CIDR ranges used for network metadata enrichment.
type CIDRDefinitions []CIDRDefinition

// UnmarshalYAML parses CIDR definitions from a sequence of strings or mapping
// objects.
func (c *CIDRDefinitions) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("cidrs: expected a YAML sequence, got kind %v", value.Kind)
	}
	definitions := make(CIDRDefinitions, 0, len(value.Content))
	for i, item := range value.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			definitions = append(definitions, CIDRDefinition{CIDR: item.Value})
		case yaml.MappingNode:
			var definition CIDRDefinition
			if err := item.Decode(&definition); err != nil {
				return fmt.Errorf("cidrs[%d]: %w", i, err)
			}
			if definition.CIDR == "" {
				return fmt.Errorf("cidrs[%d]: missing required 'cidr' field", i)
			}
			definitions = append(definitions, definition)
		default:
			return fmt.Errorf("cidrs[%d]: unexpected YAML node kind %v", i, item.Kind)
		}
	}
	*c = definitions
	return nil
}

// IncludeExclude describes include and exclude selectors for a value family.
type IncludeExclude struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// FlowLifecycle describes network flow lifetime, sampling, and deduplication
// settings.
type FlowLifecycle struct {
	MaxTrackedFlows int                     `yaml:"max_tracked_flows"`
	ActiveTimeout   Duration                `yaml:"active_timeout"`
	Deduplication   Deduplication           `yaml:"deduplication"`
	Sampling        int                     `yaml:"sampling"`
	GuessPorts      flowdef.PortGuessPolicy `yaml:"guess_ports"`
}

// DeduplicationStrategy describes the flow deduplication strategy.
type DeduplicationStrategy string

const (
	// DeduplicationStrategyNone disables flow deduplication.
	DeduplicationStrategyNone DeduplicationStrategy = "none"
	// DeduplicationStrategyFirstCome keeps flows from the first seen interface.
	DeduplicationStrategyFirstCome DeduplicationStrategy = "first_come"
)

// UnmarshalYAML parses and validates a deduplication strategy.
func (s *DeduplicationStrategy) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "strategy", s, DeduplicationStrategyNone, DeduplicationStrategyFirstCome)
}

// Deduplication describes network flow deduplication behavior.
type Deduplication struct {
	Strategy     DeduplicationStrategy `yaml:"strategy"`
	FirstComeTTL Duration              `yaml:"first_come_ttl"`
}

// InterfaceDiscoveryMode describes how network interfaces are discovered.
type InterfaceDiscoveryMode string

const (
	// InterfaceDiscoveryModeWatch watches interface changes.
	InterfaceDiscoveryModeWatch InterfaceDiscoveryMode = "watch"
	// InterfaceDiscoveryModePoll periodically polls current interfaces.
	InterfaceDiscoveryModePoll InterfaceDiscoveryMode = "poll"
)

// UnmarshalYAML parses and validates an interface discovery mode.
func (m *InterfaceDiscoveryMode) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "mode", m, InterfaceDiscoveryModeWatch, InterfaceDiscoveryModePoll)
}

// InterfaceDiscovery describes how network interfaces are discovered.
type InterfaceDiscovery struct {
	Mode         InterfaceDiscoveryMode `yaml:"mode"`
	PollInterval Duration               `yaml:"poll_interval"`
}

// NetworkEnrichment groups network metadata enrichment settings.
type NetworkEnrichment struct {
	GeoIP      GeoIPEnrichment      `yaml:"geo_ip"`
	ReverseDNS ReverseDNSEnrichment `yaml:"reverse_dns"`
}

// GeoIPEnrichment describes GeoIP enrichment provider settings.
type GeoIPEnrichment struct {
	IPInfo  Path    `yaml:"ipinfo"`
	MaxMind MaxMind `yaml:"maxmind"`
	Cache   Cache   `yaml:"cache"`
}

// Path describes a filesystem path setting.
type Path struct {
	Path string `yaml:"path"`
}

// MaxMind describes MaxMind database paths.
type MaxMind struct {
	CountryPath string `yaml:"country_path"`
	ASNPath     string `yaml:"asn_path"`
}

// ReverseDNSMode describes the reverse DNS enrichment backend.
type ReverseDNSMode string

const (
	// ReverseDNSModeNone disables reverse DNS enrichment.
	ReverseDNSModeNone ReverseDNSMode = "none"
	// ReverseDNSModeLocal uses local reverse DNS lookups.
	ReverseDNSModeLocal ReverseDNSMode = "local"
	// ReverseDNSModeEBPF uses eBPF reverse DNS data.
	ReverseDNSModeEBPF ReverseDNSMode = "ebpf"
)

// UnmarshalYAML parses and validates a reverse DNS mode.
func (m *ReverseDNSMode) UnmarshalYAML(value *yaml.Node) error {
	return unmarshalEnum(value, "mode", m, ReverseDNSModeNone, ReverseDNSModeLocal, ReverseDNSModeEBPF)
}

// Cache describes cache size and time-to-live settings.
type Cache struct {
	Size int      `yaml:"size"`
	TTL  Duration `yaml:"ttl"`
}

// ReverseDNSEnrichment describes reverse DNS enrichment settings.
type ReverseDNSEnrichment struct {
	Mode  ReverseDNSMode `yaml:"mode"`
	Cache Cache          `yaml:"cache"`
}

// FlowDiagnostics describes diagnostics for network flow capture.
type FlowDiagnostics struct {
	PrintFlows bool `yaml:"print_flows"`
}

// NetworkStats describes network statistics capture settings.
type NetworkStats struct {
	Enabled              bool              `yaml:"enabled"`
	Features             []string          `yaml:"features"`
	EndpointIdentity     EndpointIdentity  `yaml:"endpoint_identity"`
	Selection            StatsSelection    `yaml:"selection"`
	Filters              SignalFilters     `yaml:"filters"`
	Enrichment           NetworkEnrichment `yaml:"enrichment"`
	Diagnostics          StatsDiagnostics  `yaml:"diagnostics"`
	AdditionalProperties map[string]any    `yaml:",inline"`
}

// StatsSelection describes which network statistics traffic is selected.
type StatsSelection struct {
	CIDRs CIDRDefinitions `yaml:"cidrs"`
}

// StatsDiagnostics describes diagnostics for network statistics capture.
type StatsDiagnostics struct {
	PrintStats bool `yaml:"print_stats"`
}
