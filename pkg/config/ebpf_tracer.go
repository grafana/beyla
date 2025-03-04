package config

import (
	"time"

	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tcmanager"
)

// EBPFTracer configuration for eBPF programs
type EBPFTracer struct {
	// Enables logging of eBPF program events
	BpfDebug bool `yaml:"bpf_debug" env:"BEYLA_BPF_DEBUG"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"BEYLA_BPF_WAKEUP_LEN"`
	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	BatchLength int `yaml:"batch_length" env:"BEYLA_BPF_BATCH_LENGTH"`
	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"BEYLA_BPF_BATCH_TIMEOUT"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"BEYLA_BPF_TRACK_REQUEST_HEADERS"`

	HTTPRequestTimeout time.Duration `yaml:"http_request_timeout" env:"BEYLA_BPF_HTTP_REQUEST_TIMEOUT"`

	// Enables Linux Traffic Control probes for context propagation
	ContextPropagationEnabled bool `yaml:"enable_context_propagation" env:"BEYLA_BPF_ENABLE_CONTEXT_PROPAGATION"`

	// Skips checking the kernel version for bpf_loop functionality. Some modified kernels have this
	// backported prior to version 5.17.
	OverrideBPFLoopEnabled bool `yaml:"override_bpfloop_enabled" env:"BEYLA_OVERRIDE_BPF_LOOP_ENABLED"`

	// Enables Linux Traffic Control probes for context propagation
	UseTCForL7CP bool `yaml:"traffic_control_l7_context_propagation" env:"BEYLA_BPF_TC_L7_CP"`

	// Select the TC attachment backend: accepted values are 'tc' (netlink),
	// and 'tcx'
	TCBackend tcmanager.TCBackend `yaml:"traffic_control_backend" env:"BEYLA_BPF_TC_BACKEND"`

	// Disables Beyla black-box context propagation. Used for testing purposes only.
	DisableBlackBoxCP bool `yaml:"disable_black_box_cp" env:"BEYLA_BPF_DISABLE_BLACK_BOX_CP"`

	// Optimises for getting requests information immediately when request response is seen
	HighRequestVolume bool `yaml:"high_request_volume" env:"BEYLA_BPF_HIGH_REQUEST_VOLUME"`

	// Enables the heuristic based detection of SQL requests. This can be used to detect
	// talking to databases other than the ones we recognize in Beyla, like Postgres and MySQL
	HeuristicSQLDetect bool `yaml:"heuristic_sql_detect" env:"BEYLA_HEURISTIC_SQL_DETECT"`

	// Enables GPU instrumentation for CUDA kernel launches and allocations
	InstrumentGPU bool `yaml:"instrument_gpu" env:"BEYLA_INSTRUMENT_GPU"`

	// Enables debug printing of the protocol data
	ProtocolDebug bool `yaml:"protocol_debug_print" env:"BEYLA_PROTOCOL_DEBUG_PRINT"`

	// Enables Java instrumentation with the OpenTelemetry JDK Agent
	UseOTelSDKForJava bool `yaml:"use_otel_sdk_for_java" env:"BEYLA_USE_OTEL_SDK_FOR_JAVA"`
}
