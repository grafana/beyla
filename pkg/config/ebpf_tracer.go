package config

import (
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/components/ebpf/tcmanager"
)

type ContextPropagationMode uint8

const (
	ContextPropagationAll = ContextPropagationMode(iota)
	ContextPropagationHeadersOnly
	ContextPropagationIPOptionsOnly
	ContextPropagationDisabled
)

type RedisDBCacheConfig struct {
	// nolint:undoc
	Enabled bool `yaml:"enabled" env:"BEYLA_BPF_REDIS_DB_CACHE_ENABLED"`
	// nolint:undoc
	MaxSize int `yaml:"max_size" env:"BEYLA_BPF_REDIS_DB_CACHE_MAX_SIZE"`
}

// EBPFTracer configuration for eBPF programs
type EBPFTracer struct {
	// Enables logging of eBPF program events
	// nolint:undoc
	BpfDebug bool `yaml:"bpf_debug" env:"BEYLA_BPF_DEBUG"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"BEYLA_BPF_WAKEUP_LEN"`
	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	// nolint:undoc
	BatchLength int `yaml:"batch_length" env:"BEYLA_BPF_BATCH_LENGTH"`
	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	// nolint:undoc
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"BEYLA_BPF_BATCH_TIMEOUT"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"BEYLA_BPF_TRACK_REQUEST_HEADERS"`

	HTTPRequestTimeout time.Duration `yaml:"http_request_timeout" env:"BEYLA_BPF_HTTP_REQUEST_TIMEOUT"`

	// Deprecated: equivalent to ContextPropagationAll
	ContextPropagationEnabled bool `yaml:"enable_context_propagation" env:"BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION"`

	// Enables distributed context propagation.
	ContextPropagation ContextPropagationMode `yaml:"context_propagation" env:"BEYLA_BPF_CONTEXT_PROPAGATION"`

	// Skips checking the kernel version for bpf_loop functionality. Some modified kernels have this
	// backported prior to version 5.17.
	// nolint:undoc
	OverrideBPFLoopEnabled bool `yaml:"override_bpfloop_enabled" env:"BEYLA_OVERRIDE_BPF_LOOP_ENABLED"`

	// Select the TC attachment backend: accepted values are 'tc' (netlink),
	// and 'tcx'
	TCBackend tcmanager.TCBackend `yaml:"traffic_control_backend" env:"BEYLA_BPF_TC_BACKEND"`

	// Disables Beyla black-box context propagation. Used for testing purposes only.
	// nolint:undoc
	DisableBlackBoxCP bool `yaml:"disable_black_box_cp" env:"BEYLA_BPF_DISABLE_BLACK_BOX_CP"`

	// Optimises for getting requests information immediately when request response is seen
	HighRequestVolume bool `yaml:"high_request_volume" env:"BEYLA_BPF_HIGH_REQUEST_VOLUME"`

	// Enables the heuristic based detection of SQL requests. This can be used to detect
	// talking to databases other than the ones we recognize in Beyla, like Postgres and MySQL
	HeuristicSQLDetect bool `yaml:"heuristic_sql_detect" env:"BEYLA_HEURISTIC_SQL_DETECT"`

	// Enables GPU instrumentation for CUDA kernel launches and allocations
	// nolint:undoc
	InstrumentGPU bool `yaml:"instrument_gpu" env:"BEYLA_INSTRUMENT_GPU"`

	// Enables debug printing of the protocol data
	// nolint:undoc
	ProtocolDebug bool `yaml:"protocol_debug_print" env:"BEYLA_PROTOCOL_DEBUG_PRINT"`

	// Enables Java instrumentation with the OpenTelemetry JDK Agent
	// nolint:undoc
	UseOTelSDKForJava bool `yaml:"use_otel_sdk_for_java" env:"BEYLA_USE_OTEL_SDK_FOR_JAVA"`

	// nolint:undoc
	// TODO: document
	RedisDBCache RedisDBCacheConfig `yaml:"redis_db_cache"`

	// Limit max data buffer size per protocol.
	// nolint:undoc
	// TODO: document
	BufferSizes EBPFBufferSizes `yaml:"buffer_sizes" env:"BEYLA_BPF_BUFFER_SIZES"`

	// MySQL prepared statements cache size.
	// nolint:undoc
	MySQLPreparedStatementsCacheSize int `yaml:"mysql_prepared_statements_cache_size" env:"BEYLA_MYSQL_PREPARED_STATEMENTS_CACHE_SIZE"`

	// MongoDB requests cache size.
	// nolint:undoc
	MongoRequestsCacheSize int `yaml:"mongo_requests_cache_size" env:"BEYLA_MONGO_REQUESTS_CACHE_SIZE"`

	// Postgres prepared statements cache size.
	// nolint:undoc
	PostgresPreparedStatementsCacheSize int `yaml:"postgres_prepared_statements_cache_size" env:"BEYLA_POSTGRES_PREPARED_STATEMENTS_CACHE_SIZE"`

	// Kafka Topic UUID to Name cache size.
	// nolint:undoc
	KafkaTopicUUIDCacheSize int `yaml:"kafka_topic_uuid_cache_size" env:"OTEL_KAFKA_TOPIC_UUID_CACHE_SIZE"`
}

type EBPFBufferSizes struct {
	// MySQL data buffer size in bytes.
	// Min: 128 bytes, Max: 8192 bytes.
	// Valid values: 0, 128, 256, 512, 1024, 2048, 4096, 8192.
	//
	// Default: 0 (disabled).
	// nolint:undoc
	MySQL uint32 `yaml:"mysql" env:"BEYLA_BPF_BUFFER_SIZE_MYSQL"`
	// Postgres data buffer size in bytes.
	// Min: 128 bytes, Max: 8192 bytes.
	// Valid values: 0, 128, 256, 512, 1024, 2048, 4096, 8192.
	//
	// Default: 0 (disabled).
	// nolint:undoc
	Postgres uint32 `yaml:"postgres" env:"BEYLA_BPF_BUFFER_SIZE_POSTGRES"`
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
