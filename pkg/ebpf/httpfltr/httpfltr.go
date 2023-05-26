package httpfltr

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"

	ebpfcommon "github.com/grafana/ebpf-autoinstrument/pkg/ebpf/common"
	"github.com/grafana/ebpf-autoinstrument/pkg/exec"
	"golang.org/x/exp/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/grafana/ebpf-autoinstrument/pkg/goexec"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../bpf/http_sock.c -- -I../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../bpf/http_sock.c -- -I../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	Cfg        *ebpfcommon.TracerConfig
	bpfObjects bpfObjects
	closers    []io.Closer
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.Cfg.BpfDebug {
		loader = loadBpf_debug
	}
	return loader()
}

func (p *Tracer) Constants(finfo *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	if p.Cfg.SystemWide {
		return nil
	}
	return map[string]any{"current_pid": finfo.Pid}
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
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			End:      p.bpfObjects.KretprobeSysConnect,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.KprobeTcpConnect,
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

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.SocketHttpFilter}
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []ebpfcommon.HTTPRequestTrace) {
	logger := slog.With("component", "httpfltr.Tracer")
	ebpfcommon.ForwardRingbuf(
		p.Cfg, logger, p.bpfObjects.Events, toRequestTrace,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func toRequestTrace(record *ringbuf.Record) (ebpfcommon.HTTPRequestTrace, error) {
	var event bpfHttpInfoT
	result := ebpfcommon.HTTPRequestTrace{}

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
	if err != nil {
		slog.Error("Error reading generic HTTP event", err)
		return result, err
	}

	result.Type = event.Type
	result.StartMonotimeNs = event.StartMonotimeNs
	result.GoStartMonotimeNs = event.StartMonotimeNs
	result.EndMonotimeNs = event.EndMonotimeNs
	result.Status = event.Status

	source, target := event.getHostInfo()
	copy(result.Host[:], ([]byte(target)))
	copy(result.RemoteAddr[:], ([]byte(source)))
	copy(result.Method[:], ([]byte(event.getMethod())))
	copy(result.Path[:], ([]byte(event.getURL())))

	return result, nil
}

func (event *bpfHttpInfoT) getURL() string {
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

func (event *bpfHttpInfoT) getMethod() string {
	buf := string(event.Buf[:])
	space := strings.Index(buf, " ")
	if space < 0 {
		return ""
	}

	return buf[:space]
}

func formatHost(ip net.IP, port uint16) string {
	return ip.String() + ":" + strconv.FormatUint(uint64(port), 10) + "\x00"
}

func (event *bpfHttpInfoT) getHostInfo() (source, target string) {
	src := make(net.IP, net.IPv6len)
	dst := make(net.IP, net.IPv6len)
	copy(src, event.ConnInfo.S_addr[:])
	copy(dst, event.ConnInfo.D_addr[:])

	return formatHost(src, event.ConnInfo.S_port), formatHost(dst, event.ConnInfo.D_port)
}
