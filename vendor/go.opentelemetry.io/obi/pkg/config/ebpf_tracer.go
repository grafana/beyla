// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
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

const bufferSizeMax = 8192

// EBPFTracer configuration for eBPF programs
type EBPFTracer struct {
	// Enables logging of eBPF program events
	BpfDebug bool `yaml:"bpf_debug" env:"OTEL_EBPF_BPF_DEBUG"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// Must be at least 0
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"OTEL_EBPF_BPF_WAKEUP_LEN"`

	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	// Must be at least 1
	BatchLength int `yaml:"batch_length" env:"OTEL_EBPF_BPF_BATCH_LENGTH"`

	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_BPF_BATCH_TIMEOUT"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"OTEL_EBPF_BPF_TRACK_REQUEST_HEADERS"`

	// Must be at least 0
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
	TCBackend TCBackend `yaml:"traffic_control_backend" env:"OTEL_EBPF_BPF_TC_BACKEND"`

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

	// Kafka Topic UUID to Name cache size.
	KafkaTopicUUIDCacheSize int `yaml:"kafka_topic_uuid_cache_size" env:"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE"`

	// MongoDB requests cache size.
	MongoRequestsCacheSize int `yaml:"mongo_requests_cache_size" env:"OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE"`

	// Configure data extraction/parsing based on protocol
	PayloadExtraction PayloadExtraction `yaml:"payload_extraction"`
}

// Per-protocol data buffer size in bytes.
// Max: 8192 bytes.
// Default: 0 (disabled).
type EBPFBufferSizes struct {
	HTTP     uint32 `yaml:"http" env:"OTEL_EBPF_BPF_BUFFER_SIZE_HTTP"`
	MySQL    uint32 `yaml:"mysql" env:"OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL"`
	Postgres uint32 `yaml:"postgres" env:"OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES"`
}

func (c *EBPFTracer) Validate() error {
	// WakeupLen is used to calculate the wakeup_data_bytes for the ringbuf
	if c.WakeupLen < 0 {
		return errors.New("ebpf.wakeup_len in the YAML configuration file or OTEL_EBPF_BPF_WAKEUP_LEN must be at least 1")
	}
	if c.BatchLength < 1 {
		return errors.New("ebpf.batch_length in the YAML configuration file or OTEL_EBPF_BPF_BATCH_LENGTH must be at least 1")
	}

	if c.BatchTimeout <= 0 {
		return errors.New("ebpf.batch_timeout in the YAML configuration file or OTEL_EBPF_BPF_BATCH_TIMEOUT must be greater than 0")
	}

	if c.HTTPRequestTimeout < 0 {
		return errors.New("ebpf.http_request_timeout in the YAML configuration file or OTEL_EBPF_BPF_HTTP_REQUEST_TIMEOUT must be greater than or equal to 0")
	}

	if !c.TCBackend.Valid() {
		return errors.New("invalid ebpf.traffic_control_backend in the YAML configuration file or OTEL_EBPF_BPF_TC_BACKEND value, must be 'tc' or 'tcx' or 'auto'")
	}

	// remove after deleting ContextPropagationEnabled
	if c.ContextPropagationEnabled && c.ContextPropagation != ContextPropagationDisabled {
		return errors.New("ebpf.enable_context_propagation and ebpf.context_propagation in the YAML configuration file or OTEL_EBPF_BPF_ENABLE_CONTEXT_PROPAGATION and OTEL_EBPF_BPF_CONTEXT_PROPAGATION are mutually exclusive")
	}

	// TODO deprecated (REMOVE)
	// remove after deleting ContextPropagationEnabled
	if c.ContextPropagationEnabled {
		slog.Warn("DEPRECATION NOTICE: 'ebpf.enable_context_propagation' configuration option has been " +
			"deprecated and will be removed in the future - use 'ebpf.context_propagation' instead")
		c.ContextPropagation = ContextPropagationAll
	}

	if err := c.RedisDBCache.Validate(); err != nil {
		return err
	}

	if err := c.BufferSizes.Validate(); err != nil {
		return err
	}

	if c.MySQLPreparedStatementsCacheSize <= 0 {
		return errors.New("ebpf.mysql_prepared_statements_cache_size in the YAML configuration file or OTEL_EBPF_BPF_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE must be greater than 0")
	}

	if c.PostgresPreparedStatementsCacheSize <= 0 {
		return errors.New("ebpf.postgres_prepared_statements_cache_size in the YAML configuration file or OTEL_EBPF_BPF_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE must be greater than 0")
	}

	if c.KafkaTopicUUIDCacheSize <= 0 {
		return errors.New("ebpf.kafka_topic_uuid_cache_size in the YAML configuration file or OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE must be greater than 0")
	}

	if c.MongoRequestsCacheSize <= 0 {
		return errors.New("ebpf.mongo_requests_cache_size in the YAML configuration file or OTEL_EBPF_BPF_MONGO_REQUESTS_CACHE_SIZE must be greater than 0")
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

func (r RedisDBCacheConfig) Validate() error {
	if r.MaxSize <= 0 {
		return errors.New("ebpf.redis_db_cache.max_size in the YAML configuration file or OTEL_EBPF_BPF_REDIS_DB_CACHE_MAX_SIZE must be greater than 0")
	}
	return nil
}

func (b EBPFBufferSizes) Validate() error {
	if b.HTTP > bufferSizeMax {
		return fmt.Errorf("ebpf.buffer_sizes.http in YAML configuration file or OTEL_EBPF_BPF_BUFFER_SIZE_HTTP too large: %d, max is %d", b.HTTP, bufferSizeMax)
	}
	if b.MySQL > bufferSizeMax {
		return fmt.Errorf("ebpf.buffer_sizes.mysql in YAML configuration file or OTEL_EBPF_BPF_BUFFER_SIZE_MYSQL too large: %d, max is %d", b.MySQL, bufferSizeMax)
	}
	if b.Postgres > bufferSizeMax {
		return fmt.Errorf("ebpf.buffer_sizes.postgres in YAML configuration file or OTEL_EBPF_BPF_BUFFER_SIZE_POSTGRES too large: %d, max is %d", b.Postgres, bufferSizeMax)
	}
	return nil
}
