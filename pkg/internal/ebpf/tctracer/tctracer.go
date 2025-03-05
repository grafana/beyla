//go:build linux

package tctracer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tcmanager"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/tc_tracer.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/tc_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_DEBUG_TC

type Tracer struct {
	cfg          *beyla.Config
	bpfObjects   bpfObjects
	closers      []io.Closer
	log          *slog.Logger
	ifaceManager *tcmanager.InterfaceManager
	tcManager    tcmanager.TCManager
}

func New(cfg *beyla.Config) *Tracer {
	log := slog.With("component", "tc.Tracer")

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(uint32, uint32, *svc.Attrs) {}

func (p *Tracer) BlockPID(uint32, uint32) {}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {

	if !ebpfcommon.HasHostPidAccess() {
		return nil, fmt.Errorf("L4/L7 context-propagation requires host process ID access, e.g. hostPid:true")
	}

	hostNet, err := ebpfcommon.HasHostNetworkAccess()
	if err != nil {
		return nil, fmt.Errorf("failed to check for host network access while enabling L4/L7 context-propagation, error: %w", err)
	}

	if !hostNet {
		return nil, fmt.Errorf("L4/L7 context-propagation requires host network access, e.g. hostNetwork:true")
	}

	if p.cfg.EBPF.BpfDebug {
		return loadBpf_debug()
	}

	return loadBpf()
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	m["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

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
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return []ebpfcommon.SockMsg{
		{
			Program:  p.bpfObjects.BeylaPacketExtender,
			MapFD:    p.bpfObjects.bpfMaps.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return []ebpfcommon.SockOps{
		{
			Program:  p.bpfObjects.BeylaSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
	}
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) setTracerActive(active bool) {
	p.log.Debug("TCTracer active changed", "active", active)

	err := p.bpfObjects.bpfVariables.TcEnabled.Set(active)

	if err != nil {
		p.log.Error("Failed to change TCTracer active state:", "active", active, "error", err)
	}
}

func (p *Tracer) startTC(ctx context.Context) {
	if p.tcManager != nil {
		return
	}

	if p.cfg.EBPF.UseTCForL7CP {
		p.log.Info("L7 context-propagation with Linux Traffic Control enabled, not using the regular L4/L7 support.")
		return
	}

	if !p.cfg.EBPF.ContextPropagationEnabled {
		return
	}

	p.log.Info("enabling L4/L7 context-propagation with Linux Traffic Control")

	p.ifaceManager = tcmanager.NewInterfaceManager()
	p.tcManager = tcmanager.NewTCManager(p.cfg.EBPF.TCBackend)
	p.tcManager.SetInterfaceManager(p.ifaceManager)
	p.tcManager.AddProgram("tc/tc_egress", p.bpfObjects.BeylaAppEgress, tcmanager.AttachmentEgress)
	p.tcManager.AddProgram("tc/tc_ingress", p.bpfObjects.BeylaAppIngress, tcmanager.AttachmentIngress)

	p.ifaceManager.Start(ctx)
	p.setTracerActive(true)
}

func (p *Tracer) Run(ctx context.Context, _ chan<- []request.Span) {
	p.startTC(ctx)

	errorCh := p.tcManager.Errors()

	select {
	case <-ctx.Done():
	case err := <-errorCh:
		p.log.Error("TC manager returned an error, aborting", "error", err)
	}

	p.stopTC()
	p.bpfObjects.Close()
}

func (p *Tracer) stopTC() {
	p.setTracerActive(false)

	p.log.Info("removing traffic control probes")

	p.tcManager.Shutdown()
	p.tcManager = nil

	p.ifaceManager.Stop()
	p.ifaceManager.Wait()
	p.ifaceManager = nil
}
