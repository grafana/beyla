package httpfltr

import (
	"context"
	"io"
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
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/http_sock.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_tp_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

type Tracer struct {
	pidsFilter ebpfcommon.ServiceFilter
	cfg        *beyla.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	Service    *svc.ID
}

func New(cfg *beyla.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "httpfltr.Tracer")
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: ebpfcommon.CommonPIDsFilter(cfg.Discovery.SystemWide),
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

func (p *Tracer) AllowPID(pid, ns uint32, svc svc.ID) {
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

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
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
