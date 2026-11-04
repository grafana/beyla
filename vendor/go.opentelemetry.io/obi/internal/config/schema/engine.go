// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package schema // import "go.opentelemetry.io/obi/internal/config/schema"

import "go.opentelemetry.io/obi/pkg/config"

// CaptureEngine describes lower-level capture engine settings.
type CaptureEngine struct {
	Debug            EngineDebug      `yaml:"debug"`
	PIDFilter        PIDFilter        `yaml:"pid_filter"`
	Batching         Batching         `yaml:"batching"`
	Propagation      Propagation      `yaml:"propagation"`
	Traffic          Traffic          `yaml:"traffic"`
	Transactions     Transactions     `yaml:"transactions"`
	Maps             Maps             `yaml:"maps"`
	BPFFileSystem    BPFFileSystem    `yaml:"bpf_filesystem"`
	CgroupFileSystem CgroupFileSystem `yaml:"cgroup_filesystem"`
}

// EngineDebug describes capture engine debug toggles.
type EngineDebug struct {
	BPF           bool `yaml:"bpf"`
	ProtocolPrint bool `yaml:"protocol_print"`
}

// PIDFilter describes eBPF PID filtering behavior.
type PIDFilter struct {
	Disabled bool `yaml:"disabled"`
}

// Batching describes event batching behavior.
type Batching struct {
	WakeupLen    int      `yaml:"wakeup_len"`
	BatchLength  int      `yaml:"batch_length"`
	BatchTimeout Duration `yaml:"batch_timeout"`
}

// Propagation describes context propagation engine settings.
type Propagation struct {
	ContextPropagation     config.ContextPropagationMode `yaml:"context_propagation"`
	OverrideBPFLoopEnabled bool                          `yaml:"override_bpfloop_enabled"`
	DisableBlackBoxCP      bool                          `yaml:"disable_black_box_cp"`
	PopulateTraceContext   bool                          `yaml:"populate_trace_context"`
}

// Traffic describes traffic-control backend settings.
type Traffic struct {
	ControlBackend    config.TCBackend     `yaml:"control_backend"`
	HighRequestVolume bool                 `yaml:"high_request_volume"`
	ForceMapReader    config.EBPFMapReader `yaml:"force_map_reader"`
}

// Transactions describes transaction tracking settings.
type Transactions struct {
	MaxDuration Duration `yaml:"max_duration"`
}

// Maps describes eBPF map sizing settings.
type Maps struct {
	GlobalScaleFactor int `yaml:"global_scale_factor"`
}

// BPFFileSystem describes the BPF filesystem mount path.
type BPFFileSystem struct {
	Path string `yaml:"path"`
}

// CgroupFileSystem describes the host cgroup v2 mount path.
type CgroupFileSystem struct {
	Path string `yaml:"path"`
}
