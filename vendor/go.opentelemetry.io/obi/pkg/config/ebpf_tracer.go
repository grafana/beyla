// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
)

type ContextPropagationMode uint8

type RedisDBCacheConfig struct {
	Enabled bool `yaml:"enabled" env:"OTEL_EBPF_BPF_REDIS_DB_CACHE_ENABLED"`
	MaxSize int  `yaml:"max_size" env:"OTEL_EBPF_BPF_REDIS_DB_CACHE_MAX_SIZE"`
}

const (
	ContextPropagationAll = ContextPropagationMode(iota)
	ContextPropagationHeadersOnly
	ContextPropagationIPOptionsOnly
	ContextPropagationDisabled
)

// EBPFTracer configuration for eBPF programs
type EBPFTracer struct {
	// Enables logging of eBPF program events
	BpfDebug bool `yaml:"bpf_debug" env:"OTEL_EBPF_BPF_DEBUG"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"OTEL_EBPF_BPF_WAKEUP_LEN"`

	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	BatchLength int `yaml:"batch_length" env:"OTEL_EBPF_BPF_BATCH_LENGTH"`

	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_BPF_BATCH_TIMEOUT"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS"`

	HTTPRequestTimeout time.Duration `yaml:"http_request_timeout" env:"OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT"`

	// Deprecated: equivalent to ContextPropagationAll
	ContextPropagationEnabled bool `yaml:"enable_context_propagation" env:"OTEL_EBPF_BPF_ENABLE_CONTEXT_PROPAGATION"`

	// Enables distributed context propagation.
	ContextPropagation ContextPropagationMode `yaml:"context_propagation" env:"OTEL_EBPF_BPF_CONTEXT_PROPAGATION"`

	// Skips checking the kernel version for bpf_loop functionality. Some modified kernels have this
	// backported prior to version 5.17.
	OverrideBPFLoopEnabled bool `yaml:"override_bpfloop_enabled" env:"OTEL_EBPF_OVERRIDE_BPF_LOOP_ENABLED"`

	// Select the TC attachment backend: accepted values are 'tc' (netlink),
	// and 'tcx'
	TCBackend tcmanager.TCBackend `yaml:"traffic_control_backend" env:"OTEL_EBPF_BPF_TC_BACKEND"`

	// Disables Beyla black-box context propagation. Used for testing purposes only.
	DisableBlackBoxCP bool `yaml:"disable_black_box_cp" env:"OTEL_EBPF_BPF_DISABLE_BLACK_BOX_CP"`

	// Optimizes for getting requests information immediately when request response is seen
	HighRequestVolume bool `yaml:"high_request_volume" env:"OTEL_EBPF_BPF_HIGH_REQUEST_VOLUME"`

	// Enables the heuristic based detection of SQL requests. This can be used to detect
	// talking to databases other than the ones we recognize in Beyla, like Postgres and MySQL
	HeuristicSQLDetect bool `yaml:"heuristic_sql_detect" env:"OTEL_EBPF_HEURISTIC_SQL_DETECT"`

	// Enables GPU instrumentation for CUDA kernel launches and allocations
	InstrumentGPU bool `yaml:"instrument_gpu" env:"OTEL_EBPF_INSTRUMENT_GPU"`

	// Enables debug printing of the protocol data
	ProtocolDebug bool `yaml:"protocol_debug_print" env:"OTEL_EBPF_PROTOCOL_DEBUG_PRINT"`

	// Enables Java instrumentation with the OpenTelemetry JDK Agent
	UseOTelSDKForJava bool `yaml:"use_otel_sdk_for_java" env:"OTEL_EBPF_USE_OTEL_SDK_FOR_JAVA"`

	RedisDBCache RedisDBCacheConfig `yaml:"redis_db_cache"`

	// Limit max data buffer size per protocol.
	BufferSizes EBPFBufferSizes `yaml:"buffer_sizes"`

	// MySQL prepared statements cache size.
	MySQLPreparedStatementsCacheSize int `yaml:"mysql_prepared_statements_cache_size" env:"OTEL_EBPF_BPF_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE"`

	// Postgres prepared statements cache size.
	PostgresPreparedStatementsCacheSize int `yaml:"postgres_prepared_statements_cache_size" env:"OTEL_EBPF_BPF_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE"`

	// MongoDB requests cache size.
	MongoRequestsCacheSize int `yaml:"mongo_requests_cache_size" env:"OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE"`
}

type EBPFBufferSizes struct {
	// MySQL data buffer size in bytes.
	// Min: 128 bytes, Max: 8192 bytes.
	// Valid values: 0, 128, 256, 512, 1024, 2048, 4096, 8192.
	//
	// Default: 0 (disabled).
	MySQL uint32 `yaml:"mysql" env:"OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL"`
	// Postgres data buffer size in bytes.
	// Min: 128 bytes, Max: 8192 bytes.
	// Valid values: 0, 128, 256, 512, 1024, 2048, 4096, 8192.
	//
	// Default: 0 (disabled).
	Postgres uint32 `yaml:"postgres" env:"OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES"`
}

func (c *EBPFTracer) Validate() error {
	// TODO(matt): validate all the existing attributes

	switch c.BufferSizes.MySQL {
	case 0, 128, 256, 512, 1024, 2048, 4096, 8192:
		// valid sizes
	default:
		return fmt.Errorf("invalid MySQL buffer size: %d, must be one of 0, 128, 256, 512, 1024, 2048, 4096, 8192", c.BufferSizes.MySQL)
	}

	switch c.BufferSizes.Postgres {
	case 0, 128, 256, 512, 1024, 2048, 4096, 8192:
		// valid sizes
	default:
		return fmt.Errorf("invalid Postgres buffer size: %d, must be one of 0, 128, 256, 512, 1024, 2048, 4096, 8192", c.BufferSizes.Postgres)
	}

	return nil
}

func (m *ContextPropagationMode) UnmarshalText(text []byte) error {
	switch strings.TrimSpace(string(text)) {
	case "all":
		*m = ContextPropagationAll
		return nil
	case "headers":
		*m = ContextPropagationHeadersOnly
		return nil
	case "ip":
		*m = ContextPropagationIPOptionsOnly
		return nil
	case "disabled":
		*m = ContextPropagationDisabled
		return nil
	}

	return fmt.Errorf("invalid value for context_propagation: '%s'", text)
}

func (m ContextPropagationMode) MarshalText() ([]byte, error) {
	switch m {
	case ContextPropagationAll:
		return []byte("all"), nil
	case ContextPropagationHeadersOnly:
		return []byte("headers"), nil
	case ContextPropagationIPOptionsOnly:
		return []byte("ip"), nil
	case ContextPropagationDisabled:
		return []byte("disabled"), nil
	}

	return nil, fmt.Errorf("invalid context propagation mode: %d", m)
}
