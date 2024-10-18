//go:build linux

package httptracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/tc_http_tp.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/tc_http_tp.c -- -I../../../../bpf/headers -DBPF_DEBUG

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
	log := slog.With("component", "tc_http.Tracer")
	return &Tracer{
		log:            log,
		cfg:            cfg,
		qdiscs:         map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters: map[ifaces.Interface]*netlink.BpfFilter{},
	}
}

func (p *Tracer) AllowPID(uint32, uint32, *svc.ID) {}

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
	if !p.cfg.EBPF.UseLinuxTC {
		return
	}

	informer := ifaces.NewWatcher(p.cfg.ChannelBufferLen)
	registerer := ifaces.NewRegisterer(informer, p.cfg.ChannelBufferLen)
	ctx := context.Background()

	p.log.Debug("subscribing for network interface events")
	ifaceEvents, err := registerer.Subscribe(ctx)
	if err != nil {
		p.log.Error("instantiating interfaces' informer", "error", err)
		return
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Debug("stopping interfaces' listener")
				return
			case event := <-ifaceEvents:
				slog.Debug("received event", "event", event)
				switch event.Type {
				case ifaces.EventAdded:
					p.registerTC(event.Interface)
				case ifaces.EventDeleted:
					// qdiscs, ingress and egress filters are automatically deleted so we don't need to
					// specifically detach them from the ebpfFetcher
				default:
					slog.Warn("unknown event type", "event", event)
				}
			}
		}
	}()
}

func (p *Tracer) Run(ctx context.Context, _ chan<- []request.Span) {
	<-ctx.Done()

	p.bpfObjects.Close()

	p.closeTC()
}

func (p *Tracer) registerTC(iface ifaces.Interface) {
	// Load pre-compiled programs and maps into the kernel, and rewrites the configuration
	ipvlan, err := netlink.LinkByIndex(iface.Index)
	if err != nil {
		p.log.Error("failed to lookup ipvlan device", "index", iface.Index, "name", iface.Name, "error", err)
		return
	}
	qdiscAttrs := netlink.QdiscAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: qdiscAttrs,
		QdiscType:  "clsact",
	}
	if err := netlink.QdiscDel(qdisc); err == nil {
		p.log.Warn("qdisc clsact already existed. Deleted it")
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if errors.Is(err, fs.ErrExist) {
			p.log.Warn("qdisc clsact already exists. Ignoring", "error", err)
		} else {
			p.log.Error("failed to create clsact qdisc on", "index", iface.Index, "name", iface.Name, "error", err)
			return
		}
	}
	p.qdiscs[iface] = qdisc

	if err := p.registerEgress(iface, ipvlan); err != nil {
		p.log.Error("failed to install egress filters", "error", err)
	}

	if err := p.registerIngress(iface, ipvlan); err != nil {
		p.log.Error("failed to install ingres filters", "error", err)
	}
}

func (p *Tracer) registerEgress(iface ifaces.Interface, ipvlan netlink.Link) error {
	// Fetch events on egress
	egressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  3,
		Priority:  1,
	}
	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  egressAttrs,
		Fd:           p.bpfObjects.TcHttpEgress.FD(),
		Name:         "tc/tc_http_egress",
		DirectAction: true,
	}
	if err := netlink.FilterDel(egressFilter); err == nil {
		p.log.Warn("egress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(egressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			p.log.Warn("egress filter already exists. Ignoring", "error", err)
		} else {
			return fmt.Errorf("failed to create egress filter: %w", err)
		}
	}

	p.egressFilters[iface] = egressFilter
	return nil
}

func (p *Tracer) registerIngress(iface ifaces.Interface, ipvlan netlink.Link) error {
	// Fetch events on ingress
	ingressAttrs := netlink.FilterAttrs{
		LinkIndex: ipvlan.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  ingressAttrs,
		Fd:           p.bpfObjects.TcHttpIngress.FD(),
		Name:         "tc/tc_http_ingress",
		DirectAction: true,
	}
	if err := netlink.FilterDel(ingressFilter); err == nil {
		p.log.Warn("ingress filter already existed. Deleted it")
	}
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		if errors.Is(err, fs.ErrExist) {
			p.log.Warn("ingress filter already exists. Ignoring", "error", err)
		} else {
			return fmt.Errorf("failed to create ingress filter: %w", err)
		}
	}

	p.ingressFilters[iface] = ingressFilter
	return nil
}

func (p *Tracer) closeTC() {
	p.log.Info("removing traffic control probes")

	p.bpfObjects.TcHttpEgress.Close()
	p.bpfObjects.TcHttpIngress.Close()

	// cleanup egress
	for iface, ef := range p.egressFilters {
		p.log.Debug("deleting egress filter", "interface", iface)
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(ef)); err != nil {
			p.log.Error("deleting egress filter", "error", err)
		}
	}
	p.egressFilters = map[ifaces.Interface]*netlink.BpfFilter{}

	// cleanup ingress
	for iface, igf := range p.ingressFilters {
		p.log.Debug("deleting ingress filter", "interface", iface)
		if err := doIgnoreNoDev(netlink.FilterDel, netlink.Filter(igf)); err != nil {
			p.log.Error("deleting ingress filter", "error", err)
		}
	}
	p.ingressFilters = map[ifaces.Interface]*netlink.BpfFilter{}

	// cleanup qdiscs
	for iface, qd := range p.qdiscs {
		p.log.Debug("deleting Qdisc", "interface", iface)
		if err := doIgnoreNoDev(netlink.QdiscDel, netlink.Qdisc(qd)); err != nil {
			p.log.Error("deleting qdisc", "error", err)
		}
	}
	p.qdiscs = map[ifaces.Interface]*netlink.GenericQdisc{}
}

// doIgnoreNoDev runs the provided syscall over the provided device and ignores the error
// if the cause is a non-existing device (just logs the error as debug).
// If the agent is deployed as part of the Network Metrics pipeline, normally
// undeploying the FlowCollector could cause the agent to try to remove resources
// from Pods that have been removed immediately before (e.g. flowlogs-pipeline or the
// console plugin), so we avoid logging some errors that would unnecessarily raise the
// user's attention.
// This function uses generics because the set of provided functions accept different argument
// types.
func doIgnoreNoDev[T any](sysCall func(T) error, dev T) error {
	if err := sysCall(dev); err != nil {
		if errors.Is(err, unix.ENODEV) {
			slog.Error("can't delete. Ignore this error if other pods or interfaces "+
				" are also being deleted at this moment. For example, if you are undeploying "+
				" a FlowCollector or Deployment where this agent is part of",
				"error", err)
		} else {
			return err
		}
	}
	return nil
}
