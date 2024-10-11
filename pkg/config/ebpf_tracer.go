package config

import "time"

// EPPFTracer configuration for eBPF programs
type EPPFTracer struct {
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

	// BpfBaseDir specifies the base directory where the BPF pinned maps will be mounted.
	// By default, it will be /var/run/beyla
	BpfBaseDir string `yaml:"bpf_fs_base_dir" env:"BEYLA_BPF_FS_BASE_DIR"`

	// BpfPath specifies the path in the base directory where the BPF pinned maps will be mounted.
	// By default, it will be beyla-<pid>.
	BpfPath string `yaml:"bpf_fs_path" env:"BEYLA_BPF_FS_PATH"`

	// If enabled, the kprobes based HTTP request tracking will start tracking the request
	// headers to process any 'Traceparent' fields.
	TrackRequestHeaders bool `yaml:"track_request_headers" env:"BEYLA_BPF_TRACK_REQUEST_HEADERS"`

	HTTPRequestTimeout time.Duration `yaml:"http_request_timeout" env:"BEYLA_BPF_HTTP_REQUEST_TIMEOUT"`

	// Enables Linux Traffic Control probes for context propagation
	UseLinuxTC bool `yaml:"enable_traffic_control" env:"BEYLA_BPF_TC"`

	// Optimises for getting requests information immediately when request response is seen
	HighRequestVolume bool `yaml:"high_request_volume" env:"BEYLA_BPF_HIGH_REQUEST_VOLUME"`
}
