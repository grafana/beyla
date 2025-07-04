//go:build linux

package generictracer

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/gavv/monotime"
	"github.com/vishvananda/netlink"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/beyla"
	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/goexec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ifaces"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/config"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfTP ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfDebug ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfTPDebug ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf -DBPF_DEBUG -DBPF_TRACEPARENT

type Tracer struct {
	pidsFilter       ebpfcommon.ServiceFilter
	cfg              *beyla.Config
	metrics          imetrics.Reporter
	bpfObjects       BpfObjects
	closers          []io.Closer
	log              *slog.Logger
	qdiscs           map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters    map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters   map[ifaces.Interface]*netlink.BpfFilter
	instrumentedLibs ebpfcommon.InstrumentedLibsT
	libsMux          sync.Mutex
}

func tlog() *slog.Logger {
	return slog.With("component", "generic.Tracer")
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	return &Tracer{
		log:              tlog(),
		cfg:              cfg,
		metrics:          metrics,
		pidsFilter:       pidFilter,
		qdiscs:           map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:    map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:   map[ifaces.Interface]*netlink.BpfFilter{},
		instrumentedLibs: make(ebpfcommon.InstrumentedLibsT),
		libsMux:          sync.Mutex{},
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

			k := (uint64(nsid) << 32) | uint64(pid)

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
			err := p.bpfObjects.ValidPids.Put(uint32(i), segment)
			if err != nil {
				p.log.Error("Error setting up pid in BPF space, sizes of Go and BPF maps don't match", "error", err, "i", i)
			}
		}
	}
}

func (p *Tracer) AllowPID(pid, ns uint32, svc *svc.Attrs) {
	p.pidsFilter.AllowPID(pid, ns, svc, ebpfcommon.PIDTypeKProbes)
	p.rebuildValidPids()
}

func (p *Tracer) BlockPID(pid, ns uint32) {
	p.pidsFilter.BlockPID(pid, ns)
	p.rebuildValidPids()
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := LoadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = LoadBpfDebug
	}

	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation != config.ContextPropagationDisabled {
		if ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled) {
			p.log.Info("Found compatible Linux kernel, enabling trace information parsing")
			loader = LoadBpfTP
			if p.cfg.EBPF.BpfDebug {
				loader = LoadBpfTPDebug
			}
		} else {
			p.log.Info("Found incompatible Linux kernel, disabling trace information parsing")
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
			prog:  p.bpfObjects.BeylaProtocolHttp,
		},
		{
			index: 1,
			prog:  p.bpfObjects.BeylaProtocolHttp2,
		},
		{
			index: 2,
			prog:  p.bpfObjects.BeylaProtocolTcp,
		},
		{
			index: 3,
			prog:  p.bpfObjects.BeylaProtocolHttp2GrpcFrames,
		},
		{
			index: 4,
			prog:  p.bpfObjects.BeylaProtocolHttp2GrpcHandleStartFrame,
		},
		{
			index: 5,
			prog:  p.bpfObjects.BeylaProtocolHttp2GrpcHandleEndFrame,
		},
		{
			index: 6,
			prog:  p.bpfObjects.BeylaProtocolMysql,
		},
		{
			index: 7,
			prog:  p.bpfObjects.BeylaHandleBufWithArgs,
		},
	} {
		err := p.bpfObjects.JumpTable.Update(uint32(tc.index), uint32(tc.prog.FD()), ebpf.UpdateAny)
		if err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
		}
	}
}

func (p *Tracer) Constants() map[string]any {
	m := make(map[string]any, 2)

	m["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}

	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation != config.ContextPropagationDisabled {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	if p.cfg.EBPF.HighRequestVolume {
		m["high_request_volume"] = uint32(1)
	} else {
		m["high_request_volume"] = uint32(0)
	}

	if p.cfg.EBPF.DisableBlackBoxCP {
		m["disable_black_box_cp"] = uint32(1)
	} else {
		m["disable_black_box_cp"] = uint32(0)
	}

	m["mysql_buffer_size"] = p.cfg.EBPF.BufferSizes.MySQL

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
	kp := map[string]ebpfcommon.ProbeDesc{
		// Both sys accept probes use the same kretprobe.
		// We could tap into __sys_accept4, but we might be more prone to
		// issues with the internal kernel code changing.
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.BeylaKretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.BeylaKretprobeSysAccept4,
		},
		"sock_alloc": {
			Required: true,
			End:      p.bpfObjects.BeylaKretprobeSockAlloc,
		},
		"tcp_rcv_established": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeTcpRcvEstablished,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeSysConnect,
			End:      p.bpfObjects.BeylaKretprobeSysConnect,
		},
		"sock_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeSockRecvmsg,
			End:      p.bpfObjects.BeylaKretprobeSockRecvmsg,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeTcpConnect,
		},
		"tcp_close": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeTcpClose,
		},
		"tcp_sendmsg_locked": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeTcpSendmsg,
			End:      p.bpfObjects.BeylaKretprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeTcpRecvmsg,
			End:      p.bpfObjects.BeylaKretprobeTcpRecvmsg,
		},
		"tcp_cleanup_rbuf": {
			Start: p.bpfObjects.BeylaKprobeTcpCleanupRbuf, // this kprobe runs the same code as recvmsg return, we use it because kretprobes can be unreliable.
		},
		"sys_clone": {
			Required: true,
			End:      p.bpfObjects.BeylaKretprobeSysClone,
		},
		"sys_clone3": {
			Required: false,
			End:      p.bpfObjects.BeylaKretprobeSysClone,
		},
		"sys_exit": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeSysExit,
		},
		"unix_stream_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeUnixStreamRecvmsg,
			End:      p.bpfObjects.BeylaKretprobeUnixStreamRecvmsg,
		},
		"unix_stream_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeUnixStreamSendmsg,
			End:      p.bpfObjects.BeylaKretprobeUnixStreamSendmsg,
		},
	}

	if p.cfg.EBPF.ContextPropagation != config.ContextPropagationDisabled {
		// tcp_rate_check_app_limited and tcp_sendmsg_fastopen are backup
		// for tcp_sendmsg_locked which doesn't fire on certain kernels
		// if sk_msg is attached.
		kp["tcp_rate_check_app_limited"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.BeylaKprobeTcpRateCheckAppLimited,
		}
		kp["tcp_sendmsg_fastopen"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.BeylaKprobeTcpRateCheckAppLimited,
		}
	}

	return kp
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libssl.so": {
			"SSL_read": {{
				Required: false,
				Start:    p.bpfObjects.BeylaUprobeSslRead,
				End:      p.bpfObjects.BeylaUretprobeSslRead,
			}},
			"SSL_write": {{
				Required: false,
				Start:    p.bpfObjects.BeylaUprobeSslWrite,
				End:      p.bpfObjects.BeylaUretprobeSslWrite,
			}},
			"SSL_read_ex": {{
				Required: false,
				Start:    p.bpfObjects.BeylaUprobeSslReadEx,
				End:      p.bpfObjects.BeylaUretprobeSslReadEx,
			}},
			"SSL_write_ex": {{
				Required: false,
				Start:    p.bpfObjects.BeylaUprobeSslWriteEx,
				End:      p.bpfObjects.BeylaUretprobeSslWriteEx,
			}},
			"SSL_shutdown": {{
				Required: false,
				Start:    p.bpfObjects.BeylaUprobeSslShutdown,
			}},
		},
		"nginx": {
			"ngx_http_upstream_init": {{ // on upstream dispatch
				Required: false,
				Start:    p.bpfObjects.BeylaNgxHttpUpstreamInit,
			}},
			"ngx_event_connect_peer": {{
				Required: false,
				End:      p.bpfObjects.BeylaNgxEventConnectPeerRet,
			}},
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.BeylaSocketHttpFilter}
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

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
	defer p.libsMux.Unlock()

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "ino", id, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "ino", id, "error", err)
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
	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.rebuildValidPids()
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	timeoutTicker := time.NewTicker(2 * time.Second)

	go p.watchForMisclassifedEvents(ctx)
	go p.lookForTimeouts(ctx, timeoutTicker, eventsChan)
	defer timeoutTicker.Stop()

	p.log.Info("Launching p.Tracer")

	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		&p.cfg.EBPF,
		p.pidsFilter,
		p.bpfObjects.Events,
		p.metrics,
	)(ctx, append(p.closers, &p.bpfObjects), eventsChan)
}

func kernelTime(ktime uint64) time.Time {
	now := time.Now()
	delta := monotime.Now() - time.Duration(int64(ktime))

	return now.Add(-delta)
}

//nolint:cyclop
func (p *Tracer) lookForTimeouts(ctx context.Context, ticker *time.Ticker, eventsChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			if p.bpfObjects.OngoingHttp != nil {
				i := p.bpfObjects.OngoingHttp.Iterate()
				var k BpfPidConnectionInfoT
				var v BpfHttpInfoT
				for i.Next(&k, &v) {
					// Check if we have a lingering request which we've completed, as in it has EndMonotimeNs
					// but it hasn't been posted yet, likely missed by the logic that looks at finishing requests
					// where we track the full response. If we haven't updated the EndMonotimeNs in more than some
					// short interval, we are likely not going to finish this request from eBPF, so let's do it here.
					if v.EndMonotimeNs != 0 && t.After(kernelTime(v.EndMonotimeNs).Add(2*time.Second)) {
						// Must use unsafe here, the two bpfHttpInfoTs are the same but generated from different
						// ebpf2go outputs
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan((*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))
						if !ignore && err == nil {
							eventsChan.Send(p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					} else if v.EndMonotimeNs == 0 && p.cfg.EBPF.HTTPRequestTimeout.Milliseconds() > 0 && t.After(kernelTime(v.StartMonotimeNs).Add(p.cfg.EBPF.HTTPRequestTimeout)) {
						// If we don't have a request finish with endTime by the configured request timeout, terminate the
						// waiting request with a timeout 408
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan((*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))

						if !ignore && err == nil {
							s.Status = 408 // timeout
							if s.RequestStart == 0 {
								s.RequestStart = s.Start
							}
							s.End = s.Start + p.cfg.EBPF.HTTPRequestTimeout.Nanoseconds()

							eventsChan.Send(p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					}
				}
			}
		}
	}
}

func (p *Tracer) watchForMisclassifedEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ebpfcommon.MisclassifiedEvents:
			if e.EventType == ebpfcommon.EventTypeKHTTP2 {
				if p.bpfObjects.OngoingHttp2Connections != nil {
					err := p.bpfObjects.OngoingHttp2Connections.Put(
						&BpfPidConnectionInfoT{Conn: bpfConnInfoT(e.TCPInfo.ConnInfo), Pid: e.TCPInfo.Pid.HostPid},
						BpfHttp2ConnInfoDataT{Flags: e.TCPInfo.Ssl, Id: 0}, // no new connection flag (0x3)
					)
					if err != nil {
						p.log.Debug("error writing HTTP2/gRPC connection info", "error", err)
					}
				}
			}
		}
	}
}

// Cilium 0.19.0+ is adding a new private field to all the BpfConnectionInfoT
// implementations, so we can't directly do a type cast
func bpfConnInfoT(src ebpfcommon.BpfConnectionInfoT) (dst BpfConnectionInfoT) {
	dst.D_port = src.D_port
	dst.D_addr = src.D_addr
	dst.S_addr = src.S_addr
	dst.S_port = src.S_port
	return
}

func (p *Tracer) Required() bool {
	return true
}
