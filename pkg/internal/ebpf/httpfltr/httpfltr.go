package httpfltr

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	lru "github.com/hashicorp/golang-lru/v2"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf ../../../../bpf/http_sock.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_tp ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_tp_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

var activePids, _ = lru.New[uint32, svc.ID](256)
var activeServices = make(map[uint32]svc.ID)
var activeNamespaces = make(map[uint32]uint32)

type BPFHTTPInfo bpfHttpInfoT
type BPFConnInfo bpfConnectionInfoT

type HTTPInfo struct {
	BPFHTTPInfo
	Method  string
	URL     string
	Host    string
	Peer    string
	Service svc.ID
}

type PidsFilter interface {
	AllowPID(uint32)
	BlockPID(uint32)
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs() map[uint32]map[uint32]struct{}
}

type Tracer struct {
	pidsFilter PidsFilter
	cfg        *pipe.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	Service    *svc.ID
}

func New(cfg *pipe.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "httpfltr.Tracer")
	var filter PidsFilter
	if cfg.Discovery.SystemWide {
		filter = &ebpfcommon.IdentityPidsFilter{}
	} else {
		filter = ebpfcommon.CommonPIDsFilter()
	}
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: filter,
	}
}

func RegisterActiveService(pid uint32, svc svc.ID) {
	activeServices[pid] = svc
}

func UnregisterActiveService(pid uint32) {
	delete(activeServices, pid)
}

func (p *Tracer) AllowPID(pid uint32, svc svc.ID) {
	if p.bpfObjects.ValidPids != nil {
		nsid, err := ebpfcommon.FindNamespace(int32(pid))
		activeNamespaces[pid] = nsid
		if err == nil {
			err = p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: pid, Namespace: nsid}, uint8(1))
			if err != nil {
				p.log.Error("Error setting up pid in BPF space", "error", err)
			}
			// This is requied to ensure everything works when Beyla is running in pid=host mode.
			// In host mode, Beyla will find the host pid, while the bpf code matches the user pid.
			// Therefore we find all namespaced pids for the current pid we discovered and allow those too.
			otherPids, err := ebpfcommon.FindNamespacedPids(int32(pid))
			if err != nil {
				p.log.Error("Error finding namespaced pids", "error", err)
			}
			p.log.Debug("Found namespaced pids (will contain the existing pid too)", "pids", otherPids)
			for _, op := range otherPids {
				err = p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: op, Namespace: nsid}, uint8(1))
				if err != nil {
					p.log.Error("Error setting up pid in BPF space", "error", err)
				}
			}
		} else {
			p.log.Error("Error looking up namespace", "error", err)
		}
	}
	RegisterActiveService(pid, svc)
	p.pidsFilter.AllowPID(pid)
}

func (p *Tracer) BlockPID(pid uint32) {
	if p.bpfObjects.ValidPids != nil {
		ns, ok := activeNamespaces[pid]
		if ok {
			err := p.bpfObjects.ValidPids.Delete(bpfPidKeyT{Pid: pid, Namespace: ns})
			if err != nil {
				p.log.Error("Error removing pid in BPF space", "error", err)
			}
		} else {
			p.log.Warn("Couldn't find active namespace", "pid", pid)
		}
	}
	delete(activeNamespaces, pid)
	UnregisterActiveService(pid)
	p.pidsFilter.BlockPID(pid)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		kernelMajor, kernelMinor := ebpfcommon.KernelVersion()
		if kernelMajor > 5 || (kernelMajor == 5 && kernelMinor >= 17) {
			p.log.Info("Found Linux kernel later than 5.17, enabling trace information parsing", "major", kernelMajor, "minor", kernelMinor)
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
		"tcp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpRecvmsg,
			End:      p.bpfObjects.KretprobeTcpRecvmsg,
		},
	}
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(_ uint64) {}

func (p *Tracer) AlreadyInstrumentedLib(_ uint64) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		p.log.Debug("Reallowing pids")
		for nsid, pids := range p.pidsFilter.CurrentPIDs() {
			for pid := range pids {
				p.log.Debug("Reallowing pid", "pid", pid, "namespace", nsid)
				err := p.bpfObjects.ValidPids.Put(bpfPidKeyT{Pid: pid, Namespace: nsid}, uint8(1))
				if err != nil {
					if err != nil {
						p.log.Error("Error setting up pid in BPF space", "pid", pid, "namespace", nsid, "error", err)
					}
				}
			}
		}
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	p.Service = &service
	ebpfcommon.ForwardRingbuf[HTTPInfo](
		service,
		&p.cfg.EBPF, p.log, p.bpfObjects.Events,
		ReadHTTPInfoIntoSpan,
		p.pidsFilter.Filter,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func ReadHTTPInfoIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var flags uint64
	var event BPFHTTPInfo
	var result HTTPInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flags)
	if err != nil {
		return request.Span{}, true, err
	}

	err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		return request.Span{}, true, err
	}

	result = HTTPInfo{BPFHTTPInfo: event}

	// When we can't find the connection info, we signal that through making the
	// source and destination ports equal to max short. E.g. async SSL
	if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
		source, target := event.hostInfo()
		result.Host = target
		result.Peer = source
	} else {
		host, port := event.hostFromBuf()

		if port >= 0 {
			result.Host = host
			result.ConnInfo.D_port = uint16(port)
		}
	}
	result.URL = event.url()
	result.Method = event.method()
	result.Service = serviceInfo(event.Pid.HostPid)

	return httpInfoToSpan(&result), false, nil
}

func (event *BPFHTTPInfo) url() string {
	buf := string(event.Buf[:])
	space := strings.Index(buf, " ")
	if space < 0 {
		return ""
	}
	nextSpace := strings.Index(buf[space+1:], " ")
	if nextSpace < 0 {
		return ""
	}

	return buf[space+1 : nextSpace+space+1]
}

func (event *BPFHTTPInfo) method() string {
	buf := string(event.Buf[:])
	space := strings.Index(buf, " ")
	if space < 0 {
		return ""
	}

	return buf[:space]
}

func (event *BPFHTTPInfo) hostFromBuf() (string, int) {
	buf := cstr(event.Buf[:])

	host := "Host: "
	idx := strings.Index(buf, host)

	if idx < 0 {
		return "", -1
	}

	buf = buf[idx+len(host):]

	rIdx := strings.Index(buf, "\r")

	if rIdx < 0 {
		rIdx = len(buf)
	}

	host, portStr, err := net.SplitHostPort(buf[:rIdx])

	if err != nil {
		return "", -1
	}

	port, _ := strconv.Atoi(portStr)

	return host, port
}

func (event *BPFHTTPInfo) hostInfo() (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, event.ConnInfo.S_addr[:])
	copy(dst, event.ConnInfo.D_addr[:])

	return src.String(), dst.String()
}

func commName(pid uint32) string {
	procPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "comm")
	_, err := os.Stat(procPath)
	if os.IsNotExist(err) {
		return ""
	}

	name, err := os.ReadFile(procPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(name))
}

func serviceInfo(pid uint32) svc.ID {
	active, ok := activeServices[pid]
	if ok {
		return active
	}
	cached, ok := activePids.Get(pid)
	if ok {
		return cached
	}

	name := commName(pid)
	lang := exec.FindProcLanguage(int32(pid), nil)
	result := svc.ID{Name: name, SDKLanguage: lang}

	activePids.Add(pid, result)

	return result
}

func cstr(chars []uint8) string {
	addrLen := bytes.IndexByte(chars[:], 0)
	if addrLen < 0 {
		addrLen = len(chars)
	}

	return string(chars[:addrLen])
}
