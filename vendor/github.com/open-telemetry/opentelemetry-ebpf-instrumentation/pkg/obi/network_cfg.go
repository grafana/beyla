// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package obi

import (
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/flow"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/transform/cidr"
)

const (
	EbpfSourceTC   = "tc"
	EbpfSourceSock = "socket_filter"
)

type NetworkConfig struct {
	// Enable network metrics.
	// Default value is false (disabled)
	// Deprecated: add "network" to OTEL_EBPF_METRIC_FEATURES or OTEL_EBPF_PROMETHEUS_FEATURES
	// TODO Beyla 3.0: remove
	Enable bool `yaml:"enable" env:"OTEL_EBPF_NETWORK_METRICS"`

	// Specify the source type for network events, e.g tc or socket_filter. The tc implementation
	// cannot be used when there are other tc eBPF probes, e.g. Cilium CNI.
	Source string `yaml:"source" env:"OTEL_EBPF_NETWORK_SOURCE"`

	// AgentIP allows overriding the reported Agent IP address on each flow.
	AgentIP string `yaml:"agent_ip" env:"OTEL_EBPF_NETWORK_AGENT_IP"`

	// AgentIPIface specifies which interface should the agent pick the IP address from in order to
	// report it in the AgentIP field on each flow. Accepted values are: external (default), local,
	// or name:<interface name> (e.g. name:eth0).
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPIface string `yaml:"agent_ip_iface" env:"OTEL_EBPF_NETWORK_AGENT_IP_IFACE"`
	// AgentIPType specifies which type of IP address (IPv4 or IPv6 or any) should the agent report
	// in the AgentID field of each flow. Accepted values are: any (default), ipv4, ipv6.
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPType string `yaml:"agent_ip_type" env:"OTEL_EBPF_NETWORK_AGENT_IP_TYPE"`
	// Interfaces contains the interface names from where flows will be collected. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces.
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	Interfaces []string `yaml:"interfaces" env:"OTEL_EBPF_NETWORK_INTERFACES" envSeparator:","`
	// ExcludeInterfaces contains the interface names that will be excluded from flow tracing. Default:
	// "lo" (loopback).
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	ExcludeInterfaces []string `yaml:"exclude_interfaces" env:"OTEL_EBPF_NETWORK_EXCLUDE_INTERFACES" envSeparator:","`
	// Protocols causes Beyla to drop flows whose transport protocol is not in this list.
	Protocols []string `yaml:"protocols" env:"OTEL_EBPF_NETWORK_PROTOCOLS" envSeparator:","`
	// ExcludeProtocols causes Beyla to drop flows whose transport protocol is in this list.
	// If the Protocols list is already defined, ExcludeProtocols has no effect.
	ExcludeProtocols []string `yaml:"exclude_protocols" env:"OTEL_EBPF_NETWORK_EXCLUDE_PROTOCOLS" envSeparator:","`
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushed for its later export. Default value is 5000.
	// Decrease it if you see the "received message larger than max" error in Beyla logs.
	CacheMaxFlows int `yaml:"cache_max_flows" env:"OTEL_EBPF_NETWORK_CACHE_MAX_FLOWS"`
	// CacheActiveTimeout specifies the maximum duration that flows are kept in the accounting
	// cache before being flushed for its later export.
	CacheActiveTimeout time.Duration `yaml:"cache_active_timeout" env:"OTEL_EBPF_NETWORK_CACHE_ACTIVE_TIMEOUT"`
	// Deduper specifies the deduper type. Accepted values are "none" (disabled) and "first_come".
	// When enabled, it will detect duplicate flows (flows that have been detected e.g. through
	// both the physical and a virtual interface).
	// "first_come" will forward only flows from the first interface the flows are received from.
	// Default value: first_come
	//nolint:undoc
	Deduper string `yaml:"deduper" env:"OTEL_EBPF_NETWORK_DEDUPER"`
	// DeduperFCTTL specifies the expiry duration of the flows "first_come" deduplicator. After
	// a flow hasn't been received for that expiry time, the deduplicator forgets it. That means
	// that a flow from a connection that has been inactive during that period could be forwarded
	// again from a different interface.
	// If the value is not set, it will default to 2 * CacheActiveTimeout
	//nolint:undoc
	DeduperFCTTL time.Duration `yaml:"deduper_fc_ttl" env:"OTEL_EBPF_NETWORK_DEDUPER_FC_TTL"`
	// Direction allows selecting which flows to trace according to its direction. Accepted values
	// are "ingress", "egress" or "both" (default).
	//nolint:undoc
	Direction string `yaml:"direction" env:"OTEL_EBPF_NETWORK_DIRECTION"`
	// Sampling holds the rate at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector.
	Sampling int `yaml:"sampling" env:"OTEL_EBPF_NETWORK_SAMPLING"`
	// ListenInterfaces specifies the mechanism used by the agent to listen for added or removed
	// network interfaces. Accepted values are "watch" (default) or "poll".
	// If the value is "watch", interfaces are traced immediately after they are created. This is
	// the recommended setting for most configurations. "poll" value is a fallback mechanism that
	// periodically queries the current network interfaces (frequency specified by ListenPollPeriod).
	//nolint:undoc
	ListenInterfaces string `yaml:"listen_interfaces" env:"OTEL_EBPF_NETWORK_LISTEN_INTERFACES"`
	// ListenPollPeriod specifies the periodicity to query the network interfaces when the
	// ListenInterfaces value is set to "poll".
	//nolint:undoc
	ListenPollPeriod time.Duration `yaml:"listen_poll_period" env:"OTEL_EBPF_NETWORK_LISTEN_POLL_PERIOD"`

	// ReverseDNS allows flows that haven't been previously decorated with any source/destination name
	// to override the name with the network hostname of the source and destination IPs.
	// This is an experimental feature and it is not guaranteed to work on most virtualized environments
	// for external traffic.
	//nolint:undoc
	ReverseDNS flow.ReverseDNS `yaml:"reverse_dns"`
	// Print the network flows in the Standard Output, if true
	Print bool `yaml:"print_flows" env:"OTEL_EBPF_NETWORK_PRINT_FLOWS"`

	// CIDRs list, to be set as the "src.cidr" and "dst.cidr"
	// attribute as a function of the source and destination IP addresses.
	// If an IP does not match any address here, the attributes won't be set.
	// If an IP matches multiple CIDR definitions, the flow will be decorated with the
	// narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there
	// all the traffic that does not match any of the other CIDRs.
	CIDRs cidr.Definitions `yaml:"cidrs" env:"OTEL_EBPF_NETWORK_CIDRS" envSeparator:","`
}

var defaultNetworkConfig = NetworkConfig{
	Source:             EbpfSourceSock,
	AgentIPIface:       "external",
	AgentIPType:        "any",
	ExcludeInterfaces:  []string{"lo"},
	CacheMaxFlows:      5000,
	CacheActiveTimeout: 5 * time.Second,
	Deduper:            flow.DeduperFirstCome,
	Direction:          "both",
	ListenInterfaces:   "watch",
	ListenPollPeriod:   10 * time.Second,
	ReverseDNS: flow.ReverseDNS{
		Type:     flow.ReverseDNSNone,
		CacheLen: 256,
		CacheTTL: time.Hour,
	},
}
