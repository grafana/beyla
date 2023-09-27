package ebpfcommon

import (
	"bytes"
	"encoding/binary"
	"io"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/request"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target bpf -type http_request_trace bpf ../../../../bpf/http_trace.c -- -I../../../../bpf/headers

// HTTPRequestTrace contains information from an HTTP request as directly received from the
// eBPF layer. This contains low-level C structures for accurate binary read from ring buffer.
type HTTPRequestTrace bpfHttpRequestTrace

// TracerConfig configuration for eBPF programs
type TracerConfig struct {
	BpfDebug bool `yaml:"bfp_debug" env:"BPF_DEBUG"`

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

func ReadHTTPRequestTraceAsSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var event HTTPRequestTrace

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	return HTTPRequestTraceToSpan(&event), false, nil
}
