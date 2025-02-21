// Do we need a "go:build linux"? Beyla is Linux-only anyway.

package capabilitytracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/config"
	beyla_ebpf "github.com/grafana/beyla/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf ../../../../bpf/capability_tracer.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp ../../../../bpf/capability_tracer.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_debug ../../../../bpf/capability_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp_debug ../../../../bpf/capability_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

type BPFCapabilityInfo bpfCapabilityInfoT

type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *beyla.Config
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	metrics    imetrics.Reporter
}

// AddInstrumentedLibRef implements ebpf.Tracer.
func (p *Tracer) AddInstrumentedLibRef(uint64) {
}

// Updating these requires updating the constants below in pid.h
// #define MAX_CONCURRENT_PIDS 3001 // estimate: 1000 concurrent processes (including children) * 3 namespaces per pid
// #define PRIME_HASH 192053 // closest prime to 3001 * 64
const (
	maxConcurrentPids = 3001
	primeHash         = 192053
)

func pidSegmentBit(k uint64) (uint32, uint32) {
	h := uint32(k % primeHash)
	segment := h / 64
	bit := h & 63

	return segment, bit
}

func (p *Tracer) buildPidFilter() []uint64 {
	result := make([]uint64, maxConcurrentPids)
	for nsid, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
		for pid := range pids {
			// skip any pids that might've been added, but are not tracked by the kprobes
			p.log.Debug("Reallowing pid", "pid", pid, "namespace", nsid)

			k := uint64((uint64(nsid) << 32) | uint64(pid))

			segment, bit := pidSegmentBit(k)

			v := result[segment]
			v |= (1 << bit)
			result[segment] = v
		}
	}

	return result
}

func (p *Tracer) rebuildValidPids() {
	if p.bpfObjects.ValidPids != nil {
		v := p.buildPidFilter()

		p.log.Debug("number of segments in pid filter cache", "len", len(v))

		for i, segment := range v {
			err := p.bpfObjects.ValidPids.Put(uint32(i), uint64(segment))
			if err != nil {
				p.log.Error("Error setting up pid in BPF space, sizes of Go and BPF maps don't match", "error", err, "i", i)
			}
		}
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
	p.rebuildValidPids()
	p.log.Info("Allowing PID", "pid", pid)
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.rebuildValidPids()
	p.log.Info("Blocking PID", "pid", pid)
}

// AlreadyInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

// Constants implements ebpf.Tracer.
func (p *Tracer) Constants() map[string]any {
	return nil
}

// GoProbes implements ebpf.Tracer.
func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// ProcessBinary implements ebpf.Tracer.
func (p *Tracer) ProcessBinary(*exec.FileInfo) {
}

// RecordInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {
}

// RegisterOffsets implements ebpf.Tracer.
func (p *Tracer) RegisterOffsets(*exec.FileInfo, *goexec.Offsets) {
}

// SockMsgs implements ebpf.Tracer.
func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

// SockOps implements ebpf.Tracer.
func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

// SocketFilters implements ebpf.Tracer.
func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

// UProbes implements ebpf.Tracer.
func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

// UnlinkInstrumentedLib implements ebpf.Tracer.
func (p *Tracer) UnlinkInstrumentedLib(uint64) {
}

var _ beyla_ebpf.Tracer = (*Tracer)(nil)

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "capabilitytracer.Tracer")
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
	}
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	kprobes := map[string]ebpfcommon.ProbeDesc{
		"capable": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeCapable,
		},
	}

	return kprobes
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Run(ctx context.Context, ch chan<- []request.Span) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.CapabilityEvents,
		&ebpfcommon.IdentityPidsFilter{},
		// p.pidsFilter,
		p.process,
		p.log,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, ch)
}

func (p *Tracer) process(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var event BPFCapabilityInfo

	p.log.Info("capabilitytracer::process start")

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		p.log.Info("capabilitytracer::process failed to parse")
		return request.Span{}, true, err
	}

	p.log.Info("capabilitytracer::process parsed capability", "cap", event.Cap)

	return request.Span{
		Type:          request.EventTypeCapability,
		ContentLength: int64(event.Cap),
		Pid: request.PidInfo{
			HostPID: uint32(event.Pid),
		},
	}, false, nil
}
