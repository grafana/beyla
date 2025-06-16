//go:build linux

package tctracer

import (
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/tcmanager"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/tctracer"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/goexec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
)

type Tracer struct {
	cfg          *beyla.Config
	bpfObjects   tctracer.BpfObjects
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
		return tctracer.LoadBpf()
	}

	return tctracer.LoadBpf()
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

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
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

func (p *Tracer) Required() bool {
	return false
}
