// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuevent // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type cuda_kernel_launch_t -type cuda_graph_launch_t -type cuda_malloc_t -type cuda_memcpy_t -target amd64,arm64 Bpf ../../../../bpf/gpuevent/gpuevent.c -- -I../../../../bpf

const (
	EventTypeKernelLaunch = 1 // EVENT_CUDA_KERNEL_LAUNCH
	EventTypeMalloc       = 2 // EVENT_CUDA_MALLOC
	EventTypeMemcpy       = 3 // EVENT_CUDA_MEMCPY
	EventTypeGraphLaunch  = 4 // EVENT_CUDA_GRAPH_LAUNCH
)

type pidKey struct {
	Pid int32
	Ns  uint32
}

type (
	GPUCudaKernelLaunchInfo BpfCudaKernelLaunchT
	GPUCudaMallocInfo       BpfCudaMallocT
	GPUCudaMemcpyInfo       BpfCudaMemcpyT
	GPUCudaGraphLaunchInfo  BpfCudaGraphLaunchT
)

// TODO: We have a way to bring ELF file information to this Tracer struct
// via the newNonGoTracersGroup / newNonGoTracersGroupUProbes functions. Now,
// we need to figure out how to pass it to the SharedRingbuf.. not sure if thats
// possible
type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *obi.Config
	metrics          imetrics.Reporter
	bpfObjects       BpfObjects
	closers          []io.Closer
	log              *slog.Logger
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
	pidMap           map[pidKey]uint64
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "gpuevent.Tracer")

	log.Info("enabling CUDA kernel instrumentation")

	return &Tracer{
		log:              log,
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       pidFilter,
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
		pidMap:           map[pidKey]uint64{},
	}
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	return LoadBpf()
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}
	m["g_bpf_debug"] = p.cfg.EBPF.BpfDebug

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libcudart.so": {
			"cudaLaunchKernel": {{
				Start: p.bpfObjects.ObiCudaLaunch,
			}},
			"cudaGraphLaunch": {{
				Start: p.bpfObjects.ObiGraphLaunch,
			}},
			"cudaMalloc": {{
				Start: p.bpfObjects.ObiCudaMalloc,
			}},
			"cudaMemcpy": {{
				Start: p.bpfObjects.ObiCudaMemcpy,
			}},
			"cudaMemcpyAsync": {{
				Start: p.bpfObjects.ObiCudaMemcpy,
			}},
		},
	}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) SocketFilters() []*ebpf.Program { return nil }

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter { return nil }

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(id uint64, closers []io.Closer) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "ino", id, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id uint64) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id uint64) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id uint64) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "ino", id, "module", module)
	return module != nil
}

func (p *Tracer) Run(ctx context.Context, ebpfEventContext *ebpfcommon.EBPFEventContext, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.GpuEvents,
		ebpfEventContext.CommonPIDsFilter,
		p.processCudaEvent,
		p.log,
		p.metrics,
		eventsChan,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) processCudaEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	if len(record.RawSample) == 0 {
		return request.Span{}, true, errors.New("invalid ringbuffer record size")
	}

	eventType := record.RawSample[0]

	switch eventType {
	case EventTypeKernelLaunch:
		return p.readGPUKernelLaunchIntoSpan(record)
	case EventTypeGraphLaunch:
		return p.readGPUGraphLaunchIntoSpan(record)
	case EventTypeMalloc:
		return p.readGPUMallocIntoSpan(record)
	case EventTypeMemcpy:
		return p.readGPUMemcpyIntoSpan(record)
	default:
		p.log.Error("unknown cuda event")
	}

	return request.Span{}, true, nil
}

func (p *Tracer) readGPUMallocIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaMallocInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Debug("GPU Malloc", "event", event)

	return request.Span{
		Type:          request.EventTypeGPUCudaMalloc,
		ContentLength: event.Size,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}, false, nil
}

func (p *Tracer) readGPUMemcpyIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaMemcpyInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Debug("GPU Memcpy", "event", event)

	return request.Span{
		Type:          request.EventTypeGPUCudaMemcpy,
		ContentLength: event.Size,
		SubType:       int(event.Kind),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}, false, nil
}

func (p *Tracer) readGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaKernelLaunchInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Kernel Launch event
	p.log.Debug("GPU Kernel Launch", "event", event)

	return request.Span{
		Type:          request.EventTypeGPUCudaKernelLaunch,
		ContentLength: int64(event.GridX * event.GridY * event.GridZ),
		SubType:       int(event.BlockX * event.BlockY * event.BlockZ),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}, false, nil
}

func (p *Tracer) readGPUGraphLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaGraphLaunchInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Log the GPU Graph Launch event
	p.log.Debug("GPU Graph Launch", "event", event)

	return request.Span{
		Type: request.EventTypeGPUCudaGraphLaunch,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}, false, nil
}

func (p *Tracer) Required() bool {
	return false
}
