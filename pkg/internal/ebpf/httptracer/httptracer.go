//go:build linux

package httptracer

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/ebpf/tcmanager"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/tc_http_tp.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/tc_http_tp.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	cfg          *beyla.Config
	bpfObjects   bpfObjects
	closers      []io.Closer
	log          *slog.Logger
	ifaceManager *tcmanager.InterfaceManager
	tcManager    tcmanager.TCManager
}

func New(cfg *beyla.Config) *Tracer {
	log := slog.With("component", "tc_http.Tracer")

	return &Tracer{
		log: log,
		cfg: cfg,
	}
}

func (p *Tracer) AllowPID(uint32, uint32, *svc.Attrs) {}

func (p *Tracer) BlockPID(uint32, uint32) {}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	if p.cfg.EBPF.BpfDebug {
		return loadBpf_debug()
	}

	return loadBpf()
}

func (p *Tracer) SetupTailCalls() {
	for _, tc := range []struct {
		index int
		prog  *ebpf.Program
	}{
		{
			index: 0,
			prog:  p.bpfObjects.BeylaExtendSkb,
		},
	} {
		err := p.bpfObjects.TcL7JumpTable.Update(uint32(tc.index), uint32(tc.prog.FD()), ebpf.UpdateAny)

		if err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) Constants() map[string]any {
	return map[string]any{}
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

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

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

	if !p.cfg.EBPF.UseTCForL7CP {
		return
	}

	p.log.Info("enabling L7 context-propagation with Linux Traffic Control")

	if !ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled) {
		p.log.Error("cannot enable L7 context-propagation, compatible kernel required)
	}

	p.ifaceManager = tcmanager.NewInterfaceManager()
	p.tcManager = tcmanager.NewTCManager(p.cfg.EBPF.TCBackend)
	p.tcManager.SetInterfaceManager(p.ifaceManager)
	p.tcManager.AddProgram("tc/tc_http_egress", p.bpfObjects.BeylaTcHttpEgress, tcmanager.AttachmentEgress)
	p.tcManager.AddProgram("tc/tc_http_ingress", p.bpfObjects.BeylaTcHttpIngress, tcmanager.AttachmentIngress)
	p.ifaceManager.Start(ctx)
}

func (p *Tracer) Run(ctx context.Context, _ chan<- []request.Span) {
	p.startTC(ctx)

	<-ctx.Done()

	p.bpfObjects.Close()

	p.stopTC()
}

func (p *Tracer) stopTC() {
	if p.tcManager == nil {
		return
	}

	p.log.Info("removing traffic control probes")

	p.ifaceManager.Wait()
	p.ifaceManager = nil

	p.tcManager.Shutdown()
	p.tcManager = nil
}
