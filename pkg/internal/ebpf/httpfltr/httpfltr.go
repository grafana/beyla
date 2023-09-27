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
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf ../../../../bpf/http_sock.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_debug ../../../../bpf/http_sock.c -- -I../../../../bpf/headers -DBPF_DEBUG

var activePids, _ = lru.New[uint32, string](64)
var recvBufs, _ = lru.New[bpfConnectionInfoT, string](8192)

const tpLookup = "traceparent: "

type BPFHTTPInfo bpfHttpInfoT
type BPFConnInfo bpfConnectionInfoT

type HTTPInfo struct {
	BPFHTTPInfo
	Method      string
	URL         string
	Comm        string
	Host        string
	Peer        string
	Traceparent string
}

type Tracer struct {
	Cfg        *pipe.Config
	Metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	logger     *slog.Logger
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.Cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) log() *slog.Logger {
	if p.logger != nil {
		return p.logger
	}

	p.logger = slog.With("component", "httpfltr.Tracer")
	return p.logger
}

func (p *Tracer) Constants(finfo *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	if p.Cfg.SystemWide {
		return nil
	}

	m := map[string]any{"current_pid": finfo.Pid}

	npid, err := findNamespace(finfo.Pid)
	if err != nil {
		p.log().Warn("error while looking up namespace pid, namespace pid matching will not work", err)
	}

	m["current_pid_ns_id"] = npid

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
	kprobes := map[string]ebpfcommon.FunctionPrograms{
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

	// Track system exit so we can find program names of dead programs
	// when we process the events
	if p.Cfg.SystemWide {
		kprobes["sys_exit"] = ebpfcommon.FunctionPrograms{
			Required: true,
			Start:    p.bpfObjects.KprobeSysExit,
		}
		kprobes["sys_exit_group"] = ebpfcommon.FunctionPrograms{
			Required: true,
			Start:    p.bpfObjects.KprobeSysExit,
		}
	}

	return kprobes
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return map[string]map[string]ebpfcommon.FunctionPrograms{
		"libssl.so": {
			"SSL_read": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslRead,
				End:      p.bpfObjects.UretprobeSslRead,
			},
			"SSL_write": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslWrite,
				End:      p.bpfObjects.UretprobeSslWrite,
			},
			"SSL_read_ex": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslReadEx,
				End:      p.bpfObjects.UretprobeSslReadEx,
			},
			"SSL_write_ex": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslWriteEx,
				End:      p.bpfObjects.UretprobeSslWriteEx,
			},
			"SSL_do_handshake": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslDoHandshake,
				End:      p.bpfObjects.UretprobeSslDoHandshake,
			},
			"SSL_shutdown": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslShutdown,
			},
		},
		"libSystem.Security.Cryptography.Native.OpenSsl.so": {
			"CryptoNative_SslRead": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslRead,
				End:      p.bpfObjects.UretprobeSslRead,
			},
			"CryptoNative_SslWrite": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslWrite,
				End:      p.bpfObjects.UretprobeSslWrite,
			},
			"CryptoNative_SslDoHandshake": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslDoHandshake,
				End:      p.bpfObjects.UretprobeSslDoHandshake,
			},
			"CryptoNative_SslShutdown": {
				Required: false,
				Start:    p.bpfObjects.UprobeSslShutdown,
			},
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.SocketHttpFilter}
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, svcName string) {
	ebpfcommon.ForwardRingbuf[HTTPInfo](
		svcName,
		&p.Cfg.EBPF, p.log(), p.bpfObjects.Events,
		p.readHTTPInfoIntoSpan,
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func (p *Tracer) extractTraceParent(b []uint8) string {
	sLen := bytes.IndexByte(b, 0)
	if sLen < 0 {
		sLen = len(b)
	}

	s := string(b[:sLen])

	hdrEnd := strings.Index(s, "\r\n\r\n")

	if hdrEnd < 0 {
		return ""
	}

	s = s[:hdrEnd]

	ls := strings.ToLower(s)
	keyIdx := strings.Index(ls, tpLookup)
	if keyIdx >= 0 {
		end := strings.Index(ls[keyIdx:], "\r\n")
		if end < 0 {
			end = hdrEnd
		} else {
			end += keyIdx
		}
		tp := s[keyIdx+len(tpLookup) : end]
		return tp
	}

	return ""
}

func (p *Tracer) processHTTPBuf(event *bpfHttpBufT) {
	b := event.Buf[:]
	tp := p.extractTraceParent(b)
	if tp != "" {
		p.log().Debug("Found traceparent in buffer", "Traceparent", tp)
		recvBufs.Add(event.ConnInfo, tp)
	}
}

func (p *Tracer) readHTTPInfoIntoSpan(record *ringbuf.Record) (request.Span, bool, error) {
	var flags uint64
	var event BPFHTTPInfo
	var result HTTPInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flags)
	if err != nil {
		return request.Span{}, true, err
	}

	if flags != 0 {
		var buf bpfHttpBufT
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &buf)
		if err != nil {
			return request.Span{}, true, err
		}
		p.processHTTPBuf(&buf)
		return request.Span{}, true, nil
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
	if p.Cfg.SystemWide {
		result.Comm = p.serviceName(event.Pid)
	}

	tp, ok := recvBufs.Get(event.ConnInfo)

	if ok {
		p.log().Debug("Found traceparent for request", "Traceparent", tp)
		result.Traceparent = tp
		// Clean up the LRU map once we know we have what we need
		recvBufs.Remove(event.ConnInfo)
	}

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
	buf := string(event.Buf[:])
	idx := strings.Index(buf, "Host: ")

	if idx < 0 {
		return "", -1
	}

	buf = buf[idx+6:]

	rIdx := strings.Index(buf, "\r")

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

func cstr(chars []uint8) string {
	addrLen := bytes.IndexByte(chars[:], 0)
	if addrLen < 0 {
		addrLen = len(chars)
	}

	return string(chars[:addrLen])
}

func (p *Tracer) commNameOfDeadPid(pid uint32) string {
	var name [16]uint8
	err := p.bpfObjects.DeadPids.Lookup(pid, &name)
	if err != nil {
		return ""
	}

	return cstr(name[:])
}

func (p *Tracer) commName(pid uint32) string {
	procPath := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10), "comm")
	_, err := os.Stat(procPath)
	if os.IsNotExist(err) {
		return p.commNameOfDeadPid(pid)
	}

	name, err := os.ReadFile(procPath)
	if err != nil {
		p.commNameOfDeadPid(pid)
	}

	return strings.TrimSpace(string(name))
}

func (p *Tracer) serviceName(pid uint32) string {
	cached, ok := activePids.Get(pid)
	if ok {
		return cached
	}

	name := p.commName(pid)
	activePids.Add(pid, name)
	return name
}
