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

package agent

import (
	"time"
)

const (
	ListenPoll       = "poll"
	ListenWatch      = "watch"
	DeduperNone      = "none"
	DeduperFirstCome = "firstCome"
	DirectionIngress = "ingress"
	DirectionEgress  = "egress"
	DirectionBoth    = "both"

	IPTypeAny  = "any"
	IPTypeIPV4 = "ipv4"
	IPTypeIPV6 = "ipv6"

	IPIfaceExternal    = "external"
	IPIfaceLocal       = "local"
	IPIfaceNamedPrefix = "name:"
)

type Config struct {
	// AgentIP allows overriding the reported Agent IP address on each flow.
	AgentIP string `env:"AGENT_IP"`
	// AgentIPIface specifies which interface should the agent pick the IP address from in order to
	// report it in the AgentIP field on each flow. Accepted values are: external (default), local,
	// or name:<interface name> (e.g. name:eth0).
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPIface string `env:"AGENT_IP_IFACE" envDefault:"external"`
	// AgentIPType specifies which type of IP address (IPv4 or IPv6 or any) should the agent report
	// in the AgentID field of each flow. Accepted values are: any (default), ipv4, ipv6.
	// If the AgentIP configuration property is set, this property has no effect.
	AgentIPType string `env:"AGENT_IP_TYPE" envDefault:"any"`
	// Export selects the flows' exporter protocol. Accepted values are: grpc (default) or kafka
	// or ipfix+udp or ipfix+tcp.
	Export string `env:"EXPORT" envDefault:"grpc"`
	// TargetHost is the host name or IP of the target Flow collector, when the EXPORT variable is
	// set to "grpc"
	TargetHost string `env:"FLOWS_TARGET_HOST"`
	// TargetPort is the port the target Flow collector, when the EXPORT variable is set to "grpc"
	TargetPort int `env:"FLOWS_TARGET_PORT"`
	// GRPCMessageMaxFlows specifies the limit, in number of flows, of each GRPC message. Messages
	// larger than that number will be split and submitted sequentially.
	GRPCMessageMaxFlows int `env:"GRPC_MESSAGE_MAX_FLOWS" envDefault:"10000"`
	// Interfaces contains the interface names from where flows will be collected. If empty, the agent
	// will fetch all the interfaces in the system, excepting the ones listed in ExcludeInterfaces.
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	Interfaces []string `env:"INTERFACES" envSeparator:","`
	// ExcludeInterfaces contains the interface names that will be excluded from flow tracing. Default:
	// "lo" (loopback).
	// If an entry is enclosed by slashes (e.g. `/br-/`), it will match as regular expression,
	// otherwise it will be matched as a case-sensitive string.
	ExcludeInterfaces []string `env:"EXCLUDE_INTERFACES" envSeparator:"," envDefault:"lo"`
	// BuffersLength establishes the length of communication channels between the different processing
	// stages
	BuffersLength int `env:"BUFFERS_LENGTH" envDefault:"50"`
	// ExporterBufferLength establishes the length of the buffer of flow batches (not individual flows)
	// that can be accumulated before the Kafka or GRPC exporter. When this buffer is full (e.g.
	// because the Kafka or GRPC endpoint is slow), incoming flow batches will be dropped. If unset,
	// its value is the same as the BUFFERS_LENGTH property.
	ExporterBufferLength int `env:"EXPORTER_BUFFER_LENGTH"`
	// CacheMaxFlows specifies how many flows can be accumulated in the accounting cache before
	// being flushed for its later export
	CacheMaxFlows int `env:"CACHE_MAX_FLOWS" envDefault:"5000"`
	// CacheActiveTimeout specifies the maximum duration that flows are kept in the accounting
	// cache before being flushed for its later export
	CacheActiveTimeout time.Duration `env:"CACHE_ACTIVE_TIMEOUT" envDefault:"5s"`
	// Deduper specifies the deduper type. Accepted values are "none" (disabled) and "firstCome".
	// When enabled, it will detect duplicate flows (flows that have been detected e.g. through
	// both the physical and a virtual interface).
	// "firstCome" will forward only flows from the first interface the flows are received from.
	Deduper string `env:"DEDUPER" envDefault:"none"`
	// DeduperFCExpiry specifies the expiry duration of the flows "firstCome" deduplicator. After
	// a flow hasn't been received for that expiry time, the deduplicator forgets it. That means
	// that a flow from a connection that has been inactive during that period could be forwarded
	// again from a different interface.
	// If the value is not set, it will default to 2 * CacheActiveTimeout
	DeduperFCExpiry time.Duration `env:"DEDUPER_FC_EXPIRY"`
	// DeduperJustMark will just mark duplicates (boolean field) instead of dropping them.
	DeduperJustMark bool `env:"DEDUPER_JUST_MARK"`
	// Direction allows selecting which flows to trace according to its direction. Accepted values
	// are "ingress", "egress" or "both" (default).
	Direction string `env:"DIRECTION" envDefault:"both"`
	// Logger level. From more to less verbose: trace, debug, info, warn, error, fatal, panic.
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// Sampling holds the rate at which packets should be sampled and sent to the target collector.
	// E.g. if set to 100, one out of 100 packets, on average, will be sent to the target collector.
	Sampling int `env:"SAMPLING" envDefault:"0"`
	// ListenInterfaces specifies the mechanism used by the agent to listen for added or removed
	// network interfaces. Accepted values are "watch" (default) or "poll".
	// If the value is "watch", interfaces are traced immediately after they are created. This is
	// the recommended setting for most configurations. "poll" value is a fallback mechanism that
	// periodically queries the current network interfaces (frequency specified by ListenPollPeriod).
	ListenInterfaces string `env:"LISTEN_INTERFACES" envDefault:"watch"`
	// ListenPollPeriod specifies the periodicity to query the network interfaces when the
	// ListenInterfaces value is set to "poll".
	ListenPollPeriod time.Duration `env:"LISTEN_POLL_PERIOD" envDefault:"10s"`
	// KafkaBrokers is a comma-separated list of tha addresses of the brokers of the Kafka cluster
	// that this agent is configured to send messages to.
	KafkaBrokers []string `env:"KAFKA_BROKERS" envSeparator:","`
	// KafkaTopic is the name of the topic where the flows' processor will receive the flows from.
	KafkaTopic string `env:"KAFKA_TOPIC" envDefault:"network-flows"`
	// KafkaBatchMessages sets the limit on how many messages will be buffered before being sent to a
	// partition.
	KafkaBatchMessages int `env:"KAFKA_BATCH_MESSAGES" envDefault:"1000"`
	// KafkaBatchSize sets the limit, in bytes, of the maximum size of a request before being sent
	// to a partition.
	KafkaBatchSize int `env:"KAFKA_BATCH_SIZE" envDefault:"1048576"`
	// KafkaAsync. If it's true, the message writing process will never block. It also means that
	// errors are ignored since the caller will not receive the returned value.
	KafkaAsync bool `env:"KAFKA_ASYNC" envDefault:"true"`
	// KafkaCompression sets the compression codec to be used to compress messages. The accepted
	// values are: none (default), gzip, snappy, lz4, zstd.
	KafkaCompression string `env:"KAFKA_COMPRESSION" envDefault:"none"`
	// KafkaEnableTLS set true to enable TLS
	KafkaEnableTLS bool `env:"KAFKA_ENABLE_TLS" envDefault:"false"`
	// KafkaTLSInsecureSkipVerify skips server certificate verification in TLS connections
	KafkaTLSInsecureSkipVerify bool `env:"KAFKA_TLS_INSECURE_SKIP_VERIFY" envDefault:"false"`
	// KafkaTLSCACertPath is the path to the Kafka server certificate for TLS connections
	KafkaTLSCACertPath string `env:"KAFKA_TLS_CA_CERT_PATH"`
	// KafkaTLSUserCertPath is the path to the user (client) certificate for mTLS connections
	KafkaTLSUserCertPath string `env:"KAFKA_TLS_USER_CERT_PATH"`
	// KafkaTLSUserKeyPath is the path to the user (client) private key for mTLS connections
	KafkaTLSUserKeyPath string `env:"KAFKA_TLS_USER_KEY_PATH"`
	// ProfilePort sets the listening port for Go's Pprof tool. If it is not set, profile is disabled
	ProfilePort int `env:"PROFILE_PORT"`
}
