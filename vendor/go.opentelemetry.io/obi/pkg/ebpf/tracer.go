// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"io"
	"log/slog"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type Instrumentable struct {
	Type                 svc.InstrumentableType
	InstrumentationError error

	// in some runtimes, like python gunicorn, we need to allow
	// tracing both the parent pid and all of its children pid
	ChildPids []app.PID

	FileInfo *exec.FileInfo
	Offsets  *goexec.Offsets
	Tracer   *ProcessTracer

	LogEnricherEnabled bool
}

func (ie *Instrumentable) CopyToServiceAttributes() {
	ie.FileInfo.ApplyServiceDefaults(ie.Type)
}

type PIDsAccounter interface {
	// AllowPID notifies the tracer to accept traces from the given PID, sharing
	// the FileInfo so mutable service state (flags, harvested routes, k8s
	// metadata) goes through its synchronized API.
	AllowPID(app.PID, uint32, *exec.FileInfo)
	// BlockPID notifies the tracer to stop accepting traces from the process
	// with the provided PID. After receiving them via ringbuffer, it should
	// discard them.
	BlockPID(app.PID, uint32)
}

type CommonTracer interface {
	// LoadSpecs returns one SpecBundle per BPF collection. Each bundle contains
	// the collection spec, the object pointer to populate, and the constants to rewrite.
	LoadSpecs() ([]*ebpfcommon.SpecBundle, error)
	// AddCloser adds io.Closer instances that need to be invoked when the
	// Run function ends.
	AddCloser(c ...io.Closer)
	// SetupTailCalls sets up any tail call jump tables after all specs are loaded.
	SetupTailCalls()
}

type KprobesTracer interface {
	CommonTracer
	// KProbes returns a map with the name of the kernel probes that need to be
	// tapped into. Start matches kprobe, End matches kretprobe
	KProbes() map[string]ebpfcommon.ProbeDesc
	Tracepoints() map[string]ebpfcommon.ProbeDesc
}

// Tracer is an individual eBPF program (e.g. the net/http or the grpc tracers)
type Tracer interface {
	PIDsAccounter
	KprobesTracer
	// GoProbes returns a slice with the name of Go functions that need to be inspected
	// in the executable, as well as the eBPF programs that optionally need to be
	// inserted as the Go function start and end probes
	GoProbes() map[string][]*ebpfcommon.ProbeDesc
	// UProbes returns a map with the module name mapping to the uprobes that need to be
	// tapped into. Start matches uprobe, End matches uretprobe.
	// The module name key may carry a version constraint in square brackets, which causes
	// the entry to be selected only when the library's version satisfies the constraint.
	// See matchVersionedUprobeLibrary for how selection is performed.
	UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc
	// USDTProbes returns a map with the module name mapping to USDT probes.
	USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc
	// SocketFilters  returns a list of programs that need to be loaded as a
	// generic eBPF socket filter
	SocketFilters() []*ebpf.Program
	// SockMsgs returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SK_MSG eBPF programs
	SockMsgs() []ebpfcommon.SockMsg
	// SockOps returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SOCK_OPS eBPF programs
	SockOps() []ebpfcommon.SockOps
	// Iters returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING with BPF_TRACE_ITER attach type
	Iters() []*ebpfcommon.Iter
	// Tracing() returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING
	Tracing() []*ebpfcommon.Tracing
	// Probes can potentially instrument a shared library among multiple executables
	// These two functions alow programs to remember this and avoid duplicated instrumentations
	// The argument is the OS file id
	// Closers are the associated closable resources to this lib, that may be
	// closed when UnlinkInstrumentedLib() is called
	RecordInstrumentedLib(uint64, []io.Closer)
	AddInstrumentedLibRef(uint64)
	AlreadyInstrumentedLib(uint64) bool
	UnlinkInstrumentedLib(uint64)
	RegisterOffsets(*exec.FileInfo, *goexec.Offsets)
	ProcessBinary(*exec.FileInfo)
	SetEventContext(*ebpfcommon.EBPFEventContext)
	Required() bool
	Capabilities() ebpfcommon.TracerCapability
	// Run will do the action of listening for eBPF traces and forward them
	// periodically to the output channel.
	Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span])
}

// Subset of the above interface, which supports loading eBPF programs which
// are not tied to service monitoring
type UtilityTracer interface {
	KprobesTracer
	Run(context.Context)
}

type ProcessTracerType int

const (
	Go = ProcessTracerType(iota)
	Generic
)

// ProcessTracer instruments an executable with eBPF and provides the eBPF readers
// that will forward the traces to later stages in the pipeline
// TODO: We need to pass the ELFInfo from this ProcessTracker to inside a Tracer
// so that the GPU kernel event listener can find symbols names from addresses
// in the ELF file.
type ProcessTracer struct {
	log             *slog.Logger
	metrics         imetrics.Reporter
	shutdownTimeout time.Duration
	bpffsPath       string

	Type            ProcessTracerType
	Instrumentables map[uint64]*instrumenter
	Programs        []Tracer
}

func (pt *ProcessTracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	logEnricherEnabled := fi.LogEnricherEnabled()
	for i := range pt.Programs {
		if _, ok := pt.Programs[i].(*logenricher.Tracer); ok && !logEnricherEnabled {
			continue
		}
		pt.Programs[i].AllowPID(pid, ns, fi)
	}
}

func (pt *ProcessTracer) BlockPID(pid app.PID, ns uint32) {
	for i := range pt.Programs {
		pt.Programs[i].BlockPID(pid, ns)
	}
}
