package ktracer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/gavv/monotime"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/k_tracer.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/k_tracer.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/k_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/k_tracer.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

type Tracer struct {
	pidsFilter     ebpfcommon.ServiceFilter
	cfg            *beyla.Config
	metrics        imetrics.Reporter
	bpfObjects     bpfObjects
	closers        []io.Closer
	log            *slog.Logger
	qdiscs         map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters  map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters map[ifaces.Interface]*netlink.BpfFilter
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "ktracer.Tracer")
	return &Tracer{
		log:            log,
		cfg:            cfg,
		metrics:        metrics,
		pidsFilter:     ebpfcommon.CommonPIDsFilter(&cfg.Discovery),
		qdiscs:         map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:  map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters: map[ifaces.Interface]*netlink.BpfFilter{},
	}
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

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.ID) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
	p.rebuildValidPids()
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.rebuildValidPids()
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		if ebpfcommon.SupportsEBPFLoops() {
			p.log.Info("Found Linux kernel later than 5.17, enabling trace information parsing")
			loader = loadBpf_tp
			if p.cfg.EBPF.BpfDebug {
				loader = loadBpf_tp_debug
			}
		}
	}

	return loader()
}

func (p *Tracer) SetupTailCalls() {
	for _, tc := range []struct {
		index int
		prog  *ebpf.Program
	}{
		{
			index: 0,
			prog:  p.bpfObjects.ProtocolHttp,
		},
		{
			index: 1,
			prog:  p.bpfObjects.ProtocolHttp2,
		},
		{
			index: 2,
			prog:  p.bpfObjects.ProtocolTcp,
		},
	} {
		err := p.bpfObjects.JumpTable.Update(uint32(tc.index), uint32(tc.prog.FD()), ebpf.UpdateAny)

		if err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) Constants(_ *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	m := make(map[string]any, 2)

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpssl.go, otherwise we get partial events in userspace.
	if !p.cfg.Discovery.SystemWide && !p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(1)
	} else {
		m["filter_pids"] = int32(0)
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	return m
}

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
	return map[string]ebpfcommon.FunctionPrograms{
		// Both sys accept probes use the same kretprobe.
		// We could tap into __sys_accept4, but we might be more prone to
		// issues with the internal kernel code changing.
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysAccept4,
		},
		"sock_alloc": {
			Required: true,
			End:      p.bpfObjects.KretprobeSockAlloc,
		},
		"tcp_rcv_established": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRcvEstablished,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysConnect,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpConnect,
		},
		"tcp_close": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpClose,
		},
		"tcp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpSendmsg,
			End:      p.bpfObjects.KretprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRecvmsg,
			End:      p.bpfObjects.KretprobeTcpRecvmsg,
		},
		"tcp_cleanup_rbuf": {
			Start: p.bpfObjects.KprobeTcpCleanupRbuf, // this kprobe runs the same code as recvmsg return, we use it because kretprobes can be unreliable.
		},
		"sys_clone": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysClone,
		},
		"sys_clone3": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysClone,
		},
		"sys_exit": {
			Required: true,
			Start:    p.bpfObjects.KprobeSysExit,
		},
	}
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.SocketHttpFilter}
}

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
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

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span) {
	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.rebuildValidPids()
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	timeoutTicker := time.NewTicker(2 * time.Second)

	go p.watchForMisclassifedEvents()
	go p.lookForTimeouts(timeoutTicker, eventsChan)
	defer timeoutTicker.Stop()

	ebpfcommon.SharedRingbuf(
		&p.cfg.EBPF,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)

	p.closeTC()
}

func kernelTime(ktime uint64) time.Time {
	now := time.Now()
	delta := monotime.Now() - time.Duration(int64(ktime))

	return now.Add(-delta)
}

//nolint:cyclop
func (p *Tracer) lookForTimeouts(ticker *time.Ticker, eventsChan chan<- []request.Span) {
	for t := range ticker.C {
		if p.bpfObjects.OngoingHttp != nil {
			i := p.bpfObjects.OngoingHttp.Iterate()
			var k bpfPidConnectionInfoT
			var v bpfHttpInfoT
			for i.Next(&k, &v) {
				// Check if we have a lingering request which we've completed, as in it has EndMonotimeNs
				// but it hasn't been posted yet, likely missed by the logic that looks at finishing requests
				// where we track the full response. If we haven't updated the EndMonotimeNs in more than some
				// short interval, we are likely not going to finish this request from eBPF, so let's do it here.
				if v.EndMonotimeNs != 0 && t.After(kernelTime(v.EndMonotimeNs).Add(2*time.Second)) {
					// Must use unsafe here, the two bpfHttpInfoTs are the same but generated from different
					// ebpf2go outputs
					s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(*(*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))
					if !ignore && err == nil {
						eventsChan <- p.pidsFilter.Filter([]request.Span{s})
					}
					if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
						p.log.Debug("Error deleting ongoing request", "error", err)
					}
				} else if v.EndMonotimeNs == 0 && p.cfg.EBPF.HTTPRequestTimeout.Milliseconds() > 0 && t.After(kernelTime(v.StartMonotimeNs).Add(p.cfg.EBPF.HTTPRequestTimeout)) {
					// If we don't have a request finish with endTime by the configured request timeout, terminate the
					// waiting request with a timeout 408
					s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(*(*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))

					if !ignore && err == nil {
						s.Status = 408 // timeout
						if s.RequestStart == 0 {
							s.RequestStart = s.Start
						}
						s.End = s.Start + p.cfg.EBPF.HTTPRequestTimeout.Nanoseconds()

						eventsChan <- p.pidsFilter.Filter([]request.Span{s})
					}
					if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
						p.log.Debug("Error deleting ongoing request", "error", err)
					}
				}
			}
		}
	}
}

func (p *Tracer) watchForMisclassifedEvents() {
	for e := range ebpfcommon.MisclassifiedEvents {
		if e.EventType == ebpfcommon.EventTypeKHTTP2 {
			if p.bpfObjects.OngoingHttp2Connections != nil {
				err := p.bpfObjects.OngoingHttp2Connections.Put(
					&bpfPidConnectionInfoT{Conn: bpfConnectionInfoT(e.TCPInfo.ConnInfo), Pid: e.TCPInfo.Pid.HostPid},
					uint8(e.TCPInfo.Ssl),
				)
				if err != nil {
					p.log.Debug("error writing HTTP2/gRPC connection info", "error", err)
				}
			}
		}
	}
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
		Fd:           p.bpfObjects.AppEgress.FD(),
		Name:         "tc/app_tc_egress",
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
		Fd:           p.bpfObjects.AppIngress.FD(),
		Name:         "tc/app_tc_ingress",
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

	p.bpfObjects.AppEgress.Close()
	p.bpfObjects.AppIngress.Close()

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
