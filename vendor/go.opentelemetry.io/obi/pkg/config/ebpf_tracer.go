// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"time"
)

type ContextPropagationMode uint8

type RedisDBCacheConfig struct {
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_BPF_REDIS_DB_CACHE_ENABLED" validate:"boolean"`
	MaxSize int  `yaml:"max_size" env:"OTEL_EBPF_BPF_REDIS_DB_CACHE_MAX_SIZE" validate:"gt=0"`
}

const (
	ContextPropagationDisabled  ContextPropagationMode = 0
	ContextPropagationHeaders   ContextPropagationMode = 1 << 0 // HTTP headers
	ContextPropagationTCP       ContextPropagationMode = 1 << 1 // TCP options
	ContextPropagationIPOptions ContextPropagationMode = 1 << 2 // IP options

	// Convenience aliases
	ContextPropagationAll = ContextPropagationHeaders | ContextPropagationTCP | ContextPropagationIPOptions
)

// EBPFTracer configuration for eBPF programs
type EBPFTracer struct {
	// Enables logging of eBPF program events
	BpfDebug bool `yaml:"bpf_debug" env:"OTEL_EBPF_BPF_DEBUG" validate:"boolean"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// Must be at least 0
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"OTEL_EBPF_BPF_WAKEUP_LEN" validate:"gte=0"`

	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	// Must be at least 1
	BatchLength int `yaml:"batch_length" env:"OTEL_EBPF_BPF_BATCH_LENGTH" validate:"gt=0"`

	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_BPF_BATCH_TIMEOUT" validate:"gte=0"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS" validate:"boolean"`

	// Must be at least 0
	HTTPRequestTimeout time.Duration `yaml:"http_request_timeout" env:"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT" validate:"gte=0"`

	// Enables distributed context propagation.
	// Can be a combination of: headers, tcp, ip (e.g., "headers,tcp" or "all")
	ContextPropagation ContextPropagationMode `yaml:"context_propagation" env:"OTEL_EBPF_BPF_CONTEXT_PROPAGATION"`

	// Skips checking the kernel version for bpf_loop functionality. Some modified kernels have this
	// backported prior to version 5.17.
	OverrideBPFLoopEnabled bool `yaml:"override_bpfloop_enabled" env:"OTEL_EBPF_OVERRIDE_BPF_LOOP_ENABLED" validate:"boolean"`

	// Select the TC attachment backend: accepted values are 'tc' (netlink),
	// and 'tcx'
	TCBackend TCBackend `yaml:"traffic_control_backend" env:"OTEL_EBPF_BPF_TC_BACKEND" validate:"oneof=1 2 3"`

	// Disables OBI black-box context propagation. Used for testing purposes only.
	DisableBlackBoxCP bool `yaml:"disable_black_box_cp" env:"OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP" validate:"boolean"`

	// Optimizes for getting requests information immediately when request response is seen
	HighRequestVolume bool `yaml:"high_request_volume" env:"OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME" validate:"boolean"`

	// Enables the heuristic based detection of SQL requests. This can be used to detect
	// talking to databases other than the ones we recognize in OBI, like Postgres and MySQL
	HeuristicSQLDetect bool `yaml:"heuristic_sql_detect" env:"OTEL_EBPF_HEURISTIC_SQL_DETECT" validate:"boolean"`

	// Enables GPU instrumentation for CUDA kernel launches and allocations
	InstrumentGPU bool `yaml:"instrument_gpu" env:"OTEL_EBPF_INSTRUMENT_GPU" validate:"boolean"`

	// Enables debug printing of the protocol data
	ProtocolDebug bool `yaml:"protocol_debug_print" env:"OTEL_EBPF_PROTOCOL_DEBUG_PRINT" validate:"boolean"`

	// Enables Java instrumentation with the OpenTelemetry JDK Agent
	UseOTelSDKForJava bool `yaml:"use_otel_sdk_for_java" env:"OTEL_EBPF_USE_OTEL_SDK_FOR_JAVA" validate:"boolean"`

	RedisDBCache RedisDBCacheConfig `yaml:"redis_db_cache"`

	// Limit max data buffer size per protocol.
	BufferSizes EBPFBufferSizes `yaml:"buffer_sizes"`

	// MySQL prepared statements cache size.
	MySQLPreparedStatementsCacheSize int `yaml:"mysql_prepared_statements_cache_size" env:"OTEL_EBPF_BPF_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE" validate:"gt=0"`

	// Postgres prepared statements cache size.
	PostgresPreparedStatementsCacheSize int `yaml:"postgres_prepared_statements_cache_size" env:"OTEL_EBPF_BPF_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE" validate:"gt=0"`

	// Kafka Topic UUID to Name cache size.
	KafkaTopicUUIDCacheSize int `yaml:"kafka_topic_uuid_cache_size" env:"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE" validate:"gt=0"`

	// MongoDB requests cache size.
	MongoRequestsCacheSize int `yaml:"mongo_requests_cache_size" env:"OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE" validate:"gt=0"`

	// Configure data extraction/parsing based on protocol
	PayloadExtraction PayloadExtraction `yaml:"payload_extraction"`

	// Maximum time allowed for two requests to be correlated as parent -> child
	// Some programs (e.g. load generators) keep on generating requests from the same thread in perpetuity,
	// which can generate very large traces. We want to mark the parent trace as invalid if this happens.
	MaxTransactionTime time.Duration `yaml:"max_transaction_time" env:"OTEL_EBPF_BPF_MAX_TRANSACTION_TIME"`

	// DNS timeout after which we report failed event
	DNSRequestTimeout time.Duration `yaml:"dns_request_timeout" env:"OTEL_EBPF_BPF_DNS_REQUEST_TIMEOUT"`
}

// Per-protocol data buffer size in bytes.
// Max: 8192 bytes.
// Default: 0 (disabled).
type EBPFBufferSizes struct {
	HTTP     uint32 `yaml:"http" env:"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP" validate:"lte=8192"`
	MySQL    uint32 `yaml:"mysql" env:"OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL" validate:"lte=8192"`
	Postgres uint32 `yaml:"postgres" env:"OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES" validate:"lte=8192"`
}

// HasHeaders returns true if HTTP headers context propagation is enabled
func (m ContextPropagationMode) HasHeaders() bool {
	return m&ContextPropagationHeaders != 0
}

// HasTCP returns true if TCP options context propagation is enabled
func (m ContextPropagationMode) HasTCP() bool {
	return m&ContextPropagationTCP != 0
}

// HasIPOptions returns true if IP options context propagation is enabled
func (m ContextPropagationMode) HasIPOptions() bool {
	return m&ContextPropagationIPOptions != 0
}

// IsEnabled returns true if any context propagation is enabled
func (m ContextPropagationMode) IsEnabled() bool {
	return m != ContextPropagationDisabled
}

func (m *ContextPropagationMode) UnmarshalText(text []byte) error {
	str := strings.TrimSpace(string(text))

	// Handle simple cases first
	switch str {
	case "all":
		*m = ContextPropagationAll
		return nil
	case "disabled", "":
		*m = ContextPropagationDisabled
		return nil
	}

	// Parse comma-separated list
	parts := strings.Split(str, ",")
	var result ContextPropagationMode

	for _, part := range parts {
		part = strings.TrimSpace(part)
		switch part {
		case "headers", "http":
			result |= ContextPropagationHeaders
		case "tcp":
			result |= ContextPropagationTCP
		case "ip":
			result |= ContextPropagationIPOptions
		default:
			return fmt.Errorf("invalid value for context_propagation: '%s' (valid: all, disabled, headers, tcp, ip)", part)
		}
	}

	*m = result
	return nil
}

func (m ContextPropagationMode) MarshalText() ([]byte, error) {
	if m == ContextPropagationDisabled {
		return []byte("disabled"), nil
	}

	if m == ContextPropagationAll {
		return []byte("all"), nil
	}

	var parts []string
	if m.HasHeaders() {
		parts = append(parts, "headers")
	}
	if m.HasTCP() {
		parts = append(parts, "tcp")
	}
	if m.HasIPOptions() {
		parts = append(parts, "ip")
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid context propagation mode: %d", m)
	}

	return []byte(strings.Join(parts, ",")), nil
}
