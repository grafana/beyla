package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/ebpf-autoinstrument/pkg/internal/goexec"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpf -type http_request_trace bpf ../../../../bpf/http_trace.c -- -I../../../../bpf/headers

// HTTPRequestTrace contains information from an HTTP request as directly received from the
// eBPF layer. This contains low-level C structures for accurate binary read from ring buffer.
type HTTPRequestTrace bpfHttpRequestTrace

// TracerConfig configuration for eBPF programs
type TracerConfig struct {
	// Exec allows selecting the instrumented executable whose complete path contains the Exec value.
	Exec string `yaml:"executable_name" env:"EXECUTABLE_NAME"`
	// Port allows selecting the instrumented executable that owns the Port value. If this value is set (and
	// different to zero), the value of the Exec property won't take effect.
	// It's important to emphasize that if your process opens multiple HTTP/GRPC ports, the auto-instrumenter
	// will instrument all the service calls in all the ports, not only the port specified here.
	Port int `yaml:"open_port" env:"OPEN_PORT"`
	// SystemWide allows instrumentation of all HTTP (no gRPC) calls, incoming and outgoing at a system wide scale.
	// No filtering per application will be done. Using this option may result in reduced quality of information
	// gathered for certain languages, such as Golang.
	SystemWide bool   `yaml:"system_wide" env:"SYSTEM_WIDE"`
	LogLevel   string `yaml:"log_level" env:"LOG_LEVEL"`
	BpfDebug   bool   `yaml:"bfp_debug" env:"BPF_DEBUG"`

	// WakeupLen specifies how many messages need to be accumulated in the eBPF ringbuffer
	// before sending a wakeup request.
	// High values of WakeupLen could add a noticeable metric delay in services with low
	// requests/second.
	// TODO: see if there is a way to force eBPF to wakeup userspace on timeout
	WakeupLen int `yaml:"wakeup_len" env:"BPF_WAKEUP_LEN"`
	// BatchLength allows specifying how many traces will be batched at the initial
	// stage before being forwarded to the next stage
	BatchLength int `yaml:"batch_length" env:"BPF_BATCH_LENGTH"`
	// BatchTimeout specifies the timeout to forward the data batch if it didn't
	// reach the BatchLength size
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"BPF_BATCH_TIMEOUT"`

	// BpfBaseDir specifies the base directory where the BPF pinned maps will be mounted.
	// By default, it will be /var/run/beyla
	BpfBaseDir string `yaml:"bpf_fs_base_dir" env:"BPF_FS_BASE_DIR"`
}

// Probe holds the information of the instrumentation points of a given function: its start and end offsets and
// eBPF programs
type Probe struct {
	Offsets  goexec.FuncOffsets
	Programs FunctionPrograms
}

type FunctionPrograms struct {
	// Required, if true, will cancel the execution of the eBPF Tracer
	// if the function has not been found in the executable
	Required bool
	Start    *ebpf.Program
	End      *ebpf.Program
}

type Filter struct {
	io.Closer
	Fd int
}

func Read[T any](record *ringbuf.Record) (any, error) {
	var event T

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return event, err
	}

	return event, nil
}
