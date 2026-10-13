// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpuevent // import "go.opentelemetry.io/obi/pkg/internal/ebpf/gpuevent"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type cuda_kernel_launch_t -type cuda_memcpy_t -type cuda_size_event_t -type cuda_call_event_t -type cuda_device_t -type cuda_device_event_t -target $BPF_TARGETS Bpf ../../../../bpf/gpuevent/gpuevent.c -- -I../../../../bpf

const (
	EventTypeKernelLaunch      = 1  // EVENT_CUDA_KERNEL_LAUNCH
	EventTypeMalloc            = 2  // EVENT_CUDA_MALLOC
	EventTypeMemcpy            = 3  // EVENT_CUDA_MEMCPY
	EventTypeGraphLaunch       = 4  // EVENT_CUDA_GRAPH_LAUNCH
	EventTypeFree              = 5  // EVENT_CUDA_FREE
	EventTypeMemset            = 6  // EVENT_CUDA_MEMSET
	EventTypeStreamCreate      = 7  // EVENT_CUDA_STREAM_CREATE
	EventTypeStreamDestroy     = 8  // EVENT_CUDA_STREAM_DESTROY
	EventTypeEventRecord       = 9  // EVENT_CUDA_EVENT_RECORD
	EventTypeEventSynchronize  = 10 // EVENT_CUDA_EVENT_SYNCHRONIZE
	EventTypeStreamSynchronize = 11 // EVENT_CUDA_STREAM_SYNCHRONIZE
	EventTypeDeviceSynchronize = 12 // EVENT_CUDA_DEVICE_SYNCHRONIZE
	EventTypeHostRegister      = 13 // EVENT_CUDA_HOST_REGISTER
	EventTypeDeviceInfo        = 14 // EVENT_CUDA_DEVICE_INFO
)

type pidKey struct {
	Pid int32
	Ns  uint32
}

type (
	GPUCudaKernelLaunchInfo BpfCudaKernelLaunchT
	GPUCudaMemcpyInfo       BpfCudaMemcpyT
	GPUCudaSizeEventInfo    BpfCudaSizeEventT
	GPUCudaCallEventInfo    BpfCudaCallEventT
	GPUCudaDeviceEventInfo  BpfCudaDeviceEventT
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
	deviceModelsMux  sync.RWMutex
	// deviceModels maps host PIDs to their process-local CUDA device model names.
	deviceModels map[app.PID]map[uint32]string
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
		deviceModels:     map[app.PID]map[uint32]string{},
	}
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.pidsFilter.AllowPID(pid, ns, fi, ebpfcommon.PIDTypeKProbes)
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)

	p.deviceModelsMux.Lock()
	delete(p.deviceModels, pid)
	p.deviceModelsMux.Unlock()
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}

	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &p.bpfObjects, Constants: p.constants()}}, nil
}

func (p *Tracer) constants() map[string]any {
	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	filterPids := int32(1)
	if p.cfg.Discovery.BPFPidFilterOff {
		filterPids = int32(0)
	}

	m := map[string]any{
		"filter_pids": filterPids,
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
	maps.Copy(m, ebpfcommon.PIDFilterConstants())

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) Close() error {
	return ebpfcommon.CloseResources(append(p.closers, &p.bpfObjects)...)
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
				End:   p.bpfObjects.ObiCudaLaunchRet,
			}},
			"cudaGraphLaunch": {{
				Start: p.bpfObjects.ObiGraphLaunch,
				End:   p.bpfObjects.ObiGraphLaunchRet,
			}},
			"cudaMalloc": {{
				Start: p.bpfObjects.ObiCudaMalloc,
				End:   p.bpfObjects.ObiCudaMallocRet,
			}},
			"cudaFree": {{
				Start: p.bpfObjects.ObiCudaFree,
				End:   p.bpfObjects.ObiCudaFreeRet,
			}},
			"cudaMemcpy": {{
				Start: p.bpfObjects.ObiCudaMemcpy,
			}},
			"cudaMemcpyAsync": {{
				Start: p.bpfObjects.ObiCudaMemcpy,
			}},
			"cudaMemset": {{
				Start: p.bpfObjects.ObiCudaMemset,
			}},
			"cudaStreamCreate": {{
				Start: p.bpfObjects.ObiCudaStreamCreate,
			}},
			"cudaStreamCreateWithFlags": {{
				Start: p.bpfObjects.ObiCudaStreamCreateWithFlags,
			}},
			"cudaStreamCreateWithPriority": {{
				Start: p.bpfObjects.ObiCudaStreamCreateWithPriority,
			}},
			"cudaStreamDestroy": {{
				Start: p.bpfObjects.ObiCudaStreamDestroy,
			}},
			"cudaEventRecord": {{
				Start: p.bpfObjects.ObiCudaEventRecord,
			}},
			"cudaEventRecordWithFlags": {{
				Start: p.bpfObjects.ObiCudaEventRecordWithFlags,
			}},
			"cudaEventSynchronize": {{
				Start: p.bpfObjects.ObiCudaEventSynchronize,
			}},
			"cudaStreamSynchronize": {{
				Start: p.bpfObjects.ObiCudaStreamSynchronize,
			}},
			"cudaDeviceSynchronize": {{
				Start: p.bpfObjects.ObiCudaDeviceSynchronize,
			}},
			"cudaHostRegister": {{
				Start: p.bpfObjects.ObiCudaHostRegister,
			}},
			"cudaSetDevice": {{
				Start: p.bpfObjects.ObiCudaSetDevice,
				End:   p.bpfObjects.ObiCudaSetDeviceRet,
			}},
			"cudaGetDevice": {{
				Start: p.bpfObjects.ObiCudaGetDevice,
				End:   p.bpfObjects.ObiCudaGetDeviceRet,
			}},
			"cudaGetDeviceProperties": {{
				Start: p.bpfObjects.ObiCudaGetDeviceProperties,
				End:   p.bpfObjects.ObiCudaGetDevicePropertiesRet,
			}},
			"cudaGetDeviceProperties_v2": {{
				Start: p.bpfObjects.ObiCudaGetDevicePropertiesV2,
				End:   p.bpfObjects.ObiCudaGetDevicePropertiesV2Ret,
			}},
		},
		"libcuda.so": {
			"cuLaunchKernel": {{
				Start: p.bpfObjects.ObiCuLaunch,
			}},
			"cuLaunchKernelEx": {{
				Start: p.bpfObjects.ObiCuLaunchEx,
			}},
			"cuGraphLaunch": {{
				Start: p.bpfObjects.ObiCuGraphLaunch,
			}},
			"cuDeviceGetUuid": {{
				Start: p.bpfObjects.ObiCuDeviceGetUuid,
				End:   p.bpfObjects.ObiCuDeviceGetUuidRet,
			}},
			"cuDeviceGetUuid_v2": {{
				Start: p.bpfObjects.ObiCuDeviceGetUuidV2,
				End:   p.bpfObjects.ObiCuDeviceGetUuidV2Ret,
			}},
			"cuDeviceGetName": {{
				Start: p.bpfObjects.ObiCuDeviceGetName,
				End:   p.bpfObjects.ObiCuDeviceGetNameRet,
			}},
		},
	}
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

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
	module, released, err := p.instrumentedLibs.RemoveRef(id)
	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)
	p.libsMux.Unlock()

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
		return
	}

	// unlocked: every probe waits for kernel grace periods, other libraries must not queue behind it
	if released {
		if err := ebpfcommon.CloseResources(module.Closers...); err != nil {
			p.log.Debug("failed to close instrumented lib", "ino", id, "error", err)
		}
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
		p.processCudaEvent,
		ebpfEventContext.CommonPIDsFilter.Filter,
		p.log,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) processCudaEvent(record *ringbuf.Record) (request.Span, bool, error) {
	if len(record.RawSample) == 0 {
		return request.Span{}, true, errors.New("invalid ringbuffer record size")
	}

	eventType := record.RawSample[0]

	switch eventType {
	case EventTypeKernelLaunch:
		return p.readGPUKernelLaunchIntoSpan(record)
	case EventTypeMemcpy:
		return p.readGPUMemcpyIntoSpan(record)
	case EventTypeMalloc:
		return p.readGPUCudaSizeEventIntoSpan(record, request.EventTypeGPUCudaMalloc)
	case EventTypeFree:
		return p.readGPUCudaSizeEventIntoSpan(record, request.EventTypeGPUCudaFree)
	case EventTypeMemset:
		return p.readGPUCudaSizeEventIntoSpan(record, request.EventTypeGPUCudaMemset)
	case EventTypeHostRegister:
		return p.readGPUCudaSizeEventIntoSpan(record, request.EventTypeGPUCudaHostRegister)
	case EventTypeGraphLaunch:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaGraphLaunch)
	case EventTypeStreamCreate:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaStreamCreate)
	case EventTypeStreamDestroy:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaStreamDestroy)
	case EventTypeEventRecord:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaEventRecord)
	case EventTypeEventSynchronize:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaEventSynchronize)
	case EventTypeStreamSynchronize:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaStreamSynchronize)
	case EventTypeDeviceSynchronize:
		return p.readGPUCudaCallEventIntoSpan(record, request.EventTypeGPUCudaDeviceSynchronize)
	case EventTypeDeviceInfo:
		return p.readGPUCudaDeviceEventIntoSpan(record)
	default:
		p.log.Error("unknown cuda event")
	}

	return request.Span{}, true, nil
}

func (p *Tracer) readGPUCudaSizeEventIntoSpan(record *ringbuf.Record, spanType request.EventType) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaSizeEventInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	p.log.Debug("GPU size event", "type", spanType, "event", event)

	span := request.Span{
		Type:          spanType,
		ContentLength: event.Size,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}
	p.applyDeviceIdentity(&span, event.Device)

	return span, false, nil
}

func (p *Tracer) readGPUCudaCallEventIntoSpan(record *ringbuf.Record, spanType request.EventType) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaCallEventInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	p.log.Debug("GPU call event", "type", spanType, "event", event)

	span := request.Span{
		Type: spanType,
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}
	p.applyDeviceIdentity(&span, event.Device)

	return span, false, nil
}

func (p *Tracer) readGPUMemcpyIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaMemcpyInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	p.log.Debug("GPU Memcpy", "event", event)

	span := request.Span{
		Type:          request.EventTypeGPUCudaMemcpy,
		ContentLength: event.Size,
		SubType:       int(event.Kind),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}
	p.applyDeviceIdentity(&span, event.Device)

	return span, false, nil
}

func (p *Tracer) readGPUKernelLaunchIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaKernelLaunchInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	p.log.Debug("GPU Kernel Launch", "event", event)

	span := request.Span{
		Type:          request.EventTypeGPUCudaKernelLaunch,
		ContentLength: int64(event.GridX * event.GridY * event.GridZ),
		SubType:       int(event.BlockX * event.BlockY * event.BlockZ),
		Pid: request.PidInfo{
			HostPID:   app.PID(event.PidInfo.HostPid),
			UserPID:   app.PID(event.PidInfo.UserPid),
			Namespace: event.PidInfo.Ns,
		},
	}
	p.applyDeviceIdentity(&span, event.Device)

	return span, false, nil
}

// readGPUCudaDeviceEventIntoSpan caches the device identity reported by the
// introspection APIs. It learns nothing about the application's work, so it
// produces no span.
func (p *Tracer) readGPUCudaDeviceEventIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	event, err := ebpfcommon.ReinterpretCast[GPUCudaDeviceEventInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	uuid := cudaUUIDString(event.Uuid)
	model := cudaDeviceName(event.Name)

	p.log.Debug("GPU device info", "uuid", uuid, "model", model)

	if model != "" {
		pid := app.PID(event.PidInfo.HostPid)

		p.deviceModelsMux.Lock()
		models := p.deviceModels[pid]
		if models == nil {
			models = map[uint32]string{}
			p.deviceModels[pid] = models
		}
		models[event.Index] = model
		p.deviceModelsMux.Unlock()
	}

	return request.Span{}, true, nil
}

func (p *Tracer) applyDeviceIdentity(span *request.Span, device BpfCudaDeviceT) {
	if device.Known == 0 {
		return
	}

	span.CudaDeviceKnown = true
	span.CudaDeviceIndex = device.Index
	span.CudaDeviceUUID = cudaUUIDString(device.Uuid)

	p.deviceModelsMux.RLock()
	span.CudaDeviceModel = p.deviceModels[span.Pid.HostPID][device.Index]
	p.deviceModelsMux.RUnlock()
}

// cudaUUIDString renders the raw bytes of a device UUID the way nvidia-smi
// prints them behind its "GPU-" prefix. An all-zero UUID means the identity of
// the device was never observed, which maps to the empty string.
func cudaUUIDString(raw [16]uint8) string {
	if raw == [16]uint8{} {
		return ""
	}

	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
}

// cudaDeviceName trims the NUL padding of the fixed-size device model name.
func cudaDeviceName(raw [64]int8) string {
	name := make([]byte, 0, len(raw))
	for _, c := range raw {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}

	return string(name)
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}
