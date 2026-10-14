// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"time"

	"go.opentelemetry.io/obi/pkg/internal/pipe/cidr"
	"go.opentelemetry.io/obi/pkg/internal/pipe/geoip"
	"go.opentelemetry.io/obi/pkg/internal/pipe/rdns"
)

// TODO: see if there is a way to merge common fields with NetworkConfig
type StatsConfig struct {
	// AgentIP allows overriding the reported Agent IP address on each stat.
	AgentIP string `yaml:"agent_ip" env:"OTEL_EBPF_STATS_AGENT_IP" validate:"omitempty,ip" jsonschema:"type=string,format=ip"`
	// AgentIPIface specifies which interface should the agent pick the IP address from in order to
	// report it in the AgentIP field on each stat. Accepted values are: external (default), local,
	// or name:<interface name> (e.g. name:eth0).
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPIface AgentTypeIface `yaml:"agent_ip_iface" env:"OTEL_EBPF_STATS_AGENT_IP_IFACE" validate:"agentIPIface"`
	// AgentIPType specifies which type of IP address (IPv4 or IPv6 or any) should the agent report
	// in the AgentID field of each stat. Accepted values are: any (default), ipv4, ipv6.
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPType string `yaml:"agent_ip_type" env:"OTEL_EBPF_STATS_AGENT_IP_TYPE" validate:"omitempty,oneof=any ipv4 ipv6" jsonschema:"type=string,enum=any,enum=ipv4,enum=ipv6"`
	// Interfaces contains the interface names from where stats will be collected. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces.
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.

	// CIDRs list, to be set as the "src.cidr" and "dst.cidr"
	// attribute as a function of the source and destination IP addresses.
	// If an IP does not match any address here, the attributes won't be set.
	// If an IP matches multiple CIDR definitions, the stat will be decorated with the
	// narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there
	// all the traffic that does not match any of the other CIDRs.
	CIDRs cidr.Definitions `yaml:"cidrs" env:"OTEL_EBPF_STATS_CIDRS"`
	// Enables the calculation of tcp srtt of a given instrumented service

	// ReverseDNS allows stats that haven't been previously decorated with any source/destination name
	// to override the name with the network hostname of the source and destination IPs.
	// This is an experimental feature and it is not guaranteed to work on most virtualized environments
	// for external traffic.
	ReverseDNS rdns.ReverseDNS `yaml:"reverse_dns"`
	// Print enables printing the stats to the Standard Output
	Print bool `yaml:"print_stats" env:"OTEL_EBPF_STATS_PRINT_STATS" validate:"boolean"`

	GeoIP geoip.GeoIP `yaml:"geo_ip"`
}

var DefaultStatsConfig = StatsConfig{
	AgentIPIface: "external",
	AgentIPType:  "any",
	ReverseDNS: rdns.ReverseDNS{
		Type:     rdns.ReverseDNSNone,
		CacheLen: 256,
		CacheTTL: time.Hour,
	},
	GeoIP: geoip.GeoIP{
		CacheLen: 512,
		CacheTTL: time.Hour,
	},
}
