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

package beyla

import (
	"time"

	"github.com/grafana/beyla/pkg/internal/transform"
)

type NetworkConfig struct {
	// Metrics selects which metrics to report
	// Accepted values are empty or network_connection_bytes
	// Empty Metrics value would disable the Network observability in Beyla
	Metrics []string `env:"BEYLA_NETWORK_METRICS"`

	// AgentIP allows overriding the reported Agent IP address on each flow.
	AgentIP string `env:"BEYLA_NETWORK_AGENT_IP"`
	// AgentIPIface specifies which interface should the agent pick the IP address from in order to
	// report it in the AgentIP field on each flow. Accepted values are: external (default), local,
	// or name:<interface name> (e.g. name:eth0).
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPIface string `env:"BEYLA_NETWORK_AGENT_IP_IFACE" envDefault:"external"`
	// AgentIPType specifies which type of IP address (IPv4 or IPv6 or any) should the agent report
	// in the AgentID field of each flow. Accepted values are: any (default), ipv4, ipv6.
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPType string `env:"BEYLA_NETWORK_AGENT_IP_TYPE" envDefault:"any"`
	// Interfaces contains the interface names from where flows will be collected. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces.
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	Interfaces []string `env:"BEYLA_NETWORK_INTERFACES" envSeparator:","`
	// ExcludeInterfaces contains the interface names that will be excluded from flow tracing. Default:
	// "lo" (loopback).
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	ExcludeInterfaces []string `env:"BEYLA_NETWORK_EXCLUDE_INTERFACES" envSeparator:"," envDefault:"lo"`
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushed for its later export
	CacheMaxFlows int `env:"BEYLA_NETWORK_CACHE_MAX_FLOWS" envDefault:"5000"`
	// CacheActiveTimeout specifies the maximum duration that flows are kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration `env:"BEYLA_NETWORK_CACHE_ACTIVE_TIMEOUT" envDefault:"5s"`
	// Deduper specifies the deduper type. Accepted values are "none" (disabled) and "firstCome".
	// When enabled, it will detect duplicate flows (flows that have been detected e.g. through
	// both the physical and a virtual interface).
	// "firstCome" will forward only flows from the first interface the flows are received from.
	Deduper string `env:"BEYLA_NETWORK_DEDUPER" envDefault:"none"`
	// DeduperFCExpiry specifies the expiry duration of the flows "firstCome" deduplicator. After
	// a flow hasn't been received for that expiry time, the deduplicator forgets it. That means
	// that a flow from a connection that has been inactive during that period could be forwarded
	// again from a different interface.
	// If the value is not set, it will default to 2 * CacheActiveTimeout
	DeduperFCExpiry time.Duration `env:"BEYLA_NETWORK_DEDUPER_FC_EXPIRY"`
	// DeduperJustMark will just mark duplicates (boolean field) instead of dropping them.
	DeduperJustMark bool `env:"BEYLA_NETWORK_DEDUPER_JUST_MARK"`
	// Direction allows selecting which flows to trace according to its direction. Accepted values
	// are "ingress", "egress" or "both" (default).
	Direction string `env:"BEYLA_NETWORK_DIRECTION" envDefault:"both"`
	// Sampling holds the rate at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector.
	Sampling int `env:"BEYLA_NETWORK_SAMPLING" envDefault:"0"`
	// ListenInterfaces specifies the mechanism used by the agent to listen for added or removed
	// network interfaces. Accepted values are "watch" (default) or "poll".
	// If the value is "watch", interfaces are traced immediately after they are created. This is
	// the recommended setting for most configurations. "poll" value is a fallback mechanism that
	// periodically queries the current network interfaces (frequency specified by ListenPollPeriod).
	ListenInterfaces string `env:"BEYLA_NETWORK_LISTEN_INTERFACES" envDefault:"watch"`
	// ListenPollPeriod specifies the periodicity to query the network interfaces when the
	// ListenInterfaces value is set to "poll".
	ListenPollPeriod time.Duration `env:"BEYLA_NETWORK_LISTEN_POLL_PERIOD" envDefault:"10s"`

	// Property taken from FLPLite. TODO: use a hardcoded decorator. Don't let tis to be configurable
	Transform NetworkTransformConfig `yaml:"transform"`
}

// TODO: remove this and just hardcode
type NetworkTransformConfig struct {
	Rules          NetworkTransformRules `yaml:"rules" json:"rules" doc:"list of transform rules, each includes:"`
	KubeConfigPath string                `yaml:"kubeConfigPath,omitempty" json:"kubeConfigPath,omitempty" doc:"path to kubeconfig file (optional)"`
	ServicesFile   string                `yaml:"servicesFile,omitempty" json:"servicesFile,omitempty" doc:"path to services file (optional, default: /etc/services)"`
	ProtocolsFile  string                `yaml:"protocolsFile,omitempty" json:"protocolsFile,omitempty" doc:"path to protocols file (optional, default: /etc/protocols)"`
}

// TODO: quick hackathon patch. Do it properly.
func (tn *NetworkTransformConfig) Enabled() bool {
	return transform.KubernetesDecorator{Enable: transform.EnabledFalse}.Enabled()
}

func (tn *NetworkTransformConfig) GetServiceFiles() (string, string) {
	p := tn.ProtocolsFile
	if p == "" {
		p = "/etc/protocols"
	}
	s := tn.ServicesFile
	if s == "" {
		s = "/etc/services"
	}
	return p, s
}

type TransformNetworkOperationEnum struct {
	AddRegExIf    string `yaml:"add_regex_if" json:"add_regex_if" doc:"add output field if input field satisfies regex pattern from parameters field"`
	AddIf         string `yaml:"add_if" json:"add_if" doc:"add output field if input field satisfies criteria from parameters field"`
	AddSubnet     string `yaml:"add_subnet" json:"add_subnet" doc:"add output subnet field from input field and prefix length from parameters field"`
	AddLocation   string `yaml:"add_location" json:"add_location" doc:"add output location fields from input"`
	AddService    string `yaml:"add_service" json:"add_service" doc:"add output network service field from input port and parameters protocol field"`
	AddKubernetes string `yaml:"add_kubernetes" json:"add_kubernetes" doc:"add output kubernetes fields from input"`
}

type NetworkTransformRule struct {
	Input      string `yaml:"input,omitempty" json:"input,omitempty" doc:"entry input field"`
	Output     string `yaml:"output,omitempty" json:"output,omitempty" doc:"entry output field"`
	Type       string `yaml:"type,omitempty" json:"type,omitempty" enum:"TransformNetworkOperationEnum" doc:"one of the following:"`
	Parameters string `yaml:"parameters,omitempty" json:"parameters,omitempty" doc:"parameters specific to type"`
	Assignee   string `yaml:"assignee,omitempty" json:"assignee,omitempty" doc:"value needs to assign to output field"`
}

type NetworkTransformRules []NetworkTransformRule
