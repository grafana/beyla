package httpssl

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	ebpf2 "github.com/grafana/beyla/pkg/internal/ebpf"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/ebpf/httpfltr"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf ../../../../bpf/http_ssl.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_tp ../../../../bpf/http_ssl.c -- -I../../../../bpf/headers -DBPF_TRACEPARENT
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_debug ../../../../bpf/http_ssl.c -- -I../../../../bpf/headers -DBPF_DEBUG
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type http_buf_t -target amd64,arm64 bpf_tp_debug ../../../../bpf/http_ssl.c -- -I../../../../bpf/headers -DBPF_DEBUG -DBPF_TRACEPARENT

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

type pidsFilter interface {
	ebpf2.PIDsAccounter
	Filter(inputSpans []request.Span) []request.Span
	CurrentPIDs() map[uint32]map[uint32]struct{}
}

type Tracer struct {
	pidsFilter pidsFilter
	cfg        *pipe.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	Service    *svc.ID
}

func New(cfg *pipe.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "httpfltr.Tracer")
	var filter pidsFilter
	if cfg.Discovery.SystemWide {
		filter = &ebpfcommon.IdentityPidsFilter{}
	} else {
		filter = ebpfcommon.NewPIDsFilter(log)
	}
	return &Tracer{
		log:        log,
		cfg:        cfg,
		metrics:    metrics,
		pidsFilter: filter,
	}
}

func (p *Tracer) AllowPID(pid uint32) {
	p.pidsFilter.AllowPID(pid)
}

func (p *Tracer) BlockPID(pid uint32) {
	p.pidsFilter.BlockPID(pid)
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	if p.cfg.EBPF.TrackRequestHeaders {
		kernelMajor, kernelMinor := ebpf2.KernelVersion()
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
	return nil
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
	return nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	p.Service = &service
	ebpfcommon.ForwardRingbuf[HTTPInfo](
		service,
		&p.cfg.EBPF, p.log, p.bpfObjects.Events,
		httpfltr.ReadHTTPInfoIntoSpan,
		p.pidsFilter.Filter,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}
