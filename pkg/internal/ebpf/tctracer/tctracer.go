//go:build linux

package tctracer

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/v2/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/v2/pkg/internal/ebpf/tcmanager"
	"github.com/grafana/beyla/v2/pkg/internal/exec"
	"github.com/grafana/beyla/v2/pkg/internal/goexec"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/internal/svc"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/tctracer/tctracer.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/tctracer/tctracer.c -- -I../../../../bpf -I../../../../bpf -DBPF_DEBUG -DBPF_DEBUG_TC

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
		return nil, fmt.Errorf("L4 context-propagation requires host process ID access, e.g. hostPid:true")
	}

	hostNet, err := ebpfcommon.HasHostNetworkAccess()
	if err != nil {
		return nil, fmt.Errorf("failed to check for host network access while enabling IP context-propagation, error: %w", err)
	}

	if !hostNet {
		return nil, fmt.Errorf("L4 context-propagation requires host network access, e.g. hostNetwork:true")
	}

	if p.cfg.EBPF.BpfDebug {
		return loadBpf_debug()
	}

	return loadBpf()
}

func (p *Tracer) SetupTailCalls() {
}

func (p *Tracer) Constants() map[string]any {
	return nil
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
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) startTC(ctx context.Context) {
	if p.tcManager != nil {
		return
	}

	p.ifaceManager = tcmanager.NewInterfaceManager()
	p.tcManager = tcmanager.NewTCManager(p.cfg.EBPF.TCBackend)
	p.tcManager.SetInterfaceManager(p.ifaceManager)
	p.tcManager.AddProgram("tc/tc_egress", p.bpfObjects.BeylaAppEgress, tcmanager.AttachmentEgress)
	p.tcManager.AddProgram("tc/tc_ingress", p.bpfObjects.BeylaAppIngress, tcmanager.AttachmentIngress)

	p.ifaceManager.Start(ctx)
}

func (p *Tracer) Run(ctx context.Context, _ *msg.Queue[[]request.Span]) {
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
	p.log.Info("removing traffic control probes")

	p.tcManager.Shutdown()
	p.tcManager = nil

	p.ifaceManager.Stop()
	p.ifaceManager.Wait()
	p.ifaceManager = nil
}
