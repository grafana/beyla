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
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	beyla_ebpf "github.com/grafana/beyla/v2/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_debug ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type capability_info_t -target amd64,arm64 bpf_tp_debug ../../../../bpf/capabilitytracer/capability_tracer.c -- -I../../../../bpf -DBPF_DEBUG -DBPF_TRACEPARENT

var capabilities map[int32]string

func init() {
	capabilities = map[int32]string{
		0:  "CAP_CHOWN",
		1:  "CAP_DAC_OVERRIDE",
		2:  "CAP_DAC_READ_SEARCH",
		3:  "CAP_FOWNER",
		4:  "CAP_FSETID",
		5:  "CAP_KILL",
		6:  "CAP_SETGID",
		7:  "CAP_SETUID",
		8:  "CAP_SETPCAP",
		9:  "CAP_LINUX_IMMUTABLE",
		10: "CAP_NET_BIND_SERVICE",
		11: "CAP_NET_BROADCAST",
		12: "CAP_NET_ADMIN",
		13: "CAP_NET_RAW",
		14: "CAP_IPC_LOCK",
		15: "CAP_IPC_OWNER",
		16: "CAP_SYS_MODULE",
		17: "CAP_SYS_RAWIO",
		18: "CAP_SYS_CHROOT",
		19: "CAP_SYS_PTRACE",
		20: "CAP_SYS_PACCT",
		21: "CAP_SYS_ADMIN",
		22: "CAP_SYS_BOOT",
		23: "CAP_SYS_NICE",
		24: "CAP_SYS_RESOURCE",
		25: "CAP_SYS_TIME",
		26: "CAP_SYS_TTY_CONFIG",
		27: "CAP_MKNOD",
		28: "CAP_LEASE",
		29: "CAP_AUDIT_WRITE",
		30: "CAP_AUDIT_CONTROL",
		31: "CAP_SETFCAP",
		32: "CAP_MAC_OVERRIDE",
		33: "CAP_MAC_ADMIN",
		34: "CAP_SYSLOG",
		35: "CAP_WAKE_ALARM",
		36: "CAP_BLOCK_SUSPEND",
		37: "CAP_AUDIT_READ",
		38: "CAP_PERFMON",
		39: "CAP_BPF",
		40: "CAP_CHECKPOINT_RESTORE",
	}
}

type BPFCapabilityInfo bpfCapabilityInfoT

type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *beyla.Config
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
}

// AddInstrumentedLibRef implements ebpf.Tracer.
func (p *Tracer) AddInstrumentedLibRef(uint64) {
}

func (p *Tracer) AllowPID(uint32, uint32, *svc.Attrs) {
}

func (p *Tracer) BlockPID(uint32, uint32) {
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

func New(cfg *beyla.Config) *Tracer {
	log := slog.With("component", "capabilitytracer.Tracer")
	return &Tracer{
		log:        log,
		cfg:        cfg,
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

func (p *Tracer) Run(ctx context.Context, eventsChan *msg.Queue[[]request.Span]) {
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.CapabilityEvents,
		&ebpfcommon.IdentityPidsFilter{},
		p.process,
		p.log,
		&imetrics.NoopReporter{},
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) process(_ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var event BPFCapabilityInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		p.log.Error("failed to parse capability")
		return request.Span{}, true, err
	}

	p.log.Info("a capability was used", "PID", event.Pid, "capability", capabilityName(event.Cap), "process", processName(event.Comm))

	return request.Span{}, false, nil
}

func capabilityName(capabilityID int32) string {
	return capabilities[capabilityID]
}

func processName(processName [16]uint8) string {
	return unix.ByteSliceToString(processName[:])
}

func (p *Tracer) Required() bool {
	return true
}
