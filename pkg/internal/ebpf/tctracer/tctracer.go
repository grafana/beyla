//go:build linux

package tctracer

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/tc_tracer.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/tc_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_DEBUG_TC

type Tracer struct {
	cfg            *beyla.Config
	bpfObjects     bpfObjects
	closers        []io.Closer
	log            *slog.Logger
	qdiscs         map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters  map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter
}

func New(cfg *beyla.Config) *Tracer {
	log := slog.With("component", "tc.Tracer")
	return &Tracer{
		log:            log,
		cfg:            cfg,
		qdiscs:         map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters: map[ifaces.Interface]*netlink.BpfFilter{},
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

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) Constants() map[string]any {
	return map[string]any{}
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) {}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(uint64) {}

func (p *Tracer) UnlinkInstrumentedLib(uint64) {}

func (p *Tracer) AddModuleCloser(uint64, ...io.Closer) {}

func (p *Tracer) AlreadyInstrumentedLib(uint64) bool {
	return false
}

func (p *Tracer) SetupTC() {
	if !p.cfg.EBPF.UseTCForCP {
		return
	}

	p.log.Info("enabling L4 context-propagation with Linux Traffic Control")

	ebpfcommon.WatchAndRegisterTC(context.Background(), p.cfg.ChannelBufferLen, p.registerTC, p.log)
}

func (p *Tracer) Run(ctx context.Context, _ chan<- []request.Span) {
	<-ctx.Done()

	p.bpfObjects.Close()

	p.closeTC()
}

func (p *Tracer) registerTC(iface ifaces.Interface) {
	links := ebpfcommon.RegisterTC(iface, p.bpfObjects.AppEgress.FD(), p.bpfObjects.AppIngress.FD(), p.log)
	if links == nil {
		return
	}

	p.qdiscs[iface] = links.Qdisc
	p.ingressFilters[iface] = links.IngressFilter
	p.egressFilters[iface] = links.EgressFilter
}

func (p *Tracer) closeTC() {
	p.log.Info("removing traffic control probes")

	p.bpfObjects.AppEgress.Close()
	p.bpfObjects.AppIngress.Close()

	ebpfcommon.CloseTCLinks(p.qdiscs, p.egressFilters, p.ingressFilters, p.log)

	p.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	p.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}
	p.qdiscs = map[ifaces.Interface]*netlink.GenericQdisc{}
}
