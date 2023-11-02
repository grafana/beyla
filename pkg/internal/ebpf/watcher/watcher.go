package watcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 bpf ../../../../bpf/watch_helper.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 bpf_debug ../../../../bpf/watch_helper.c -- -I../../../../bpf/headers -DBPF_DEBUG

var newPortOfInterest = true // set to true initially to let port scanning run once at least
var mux = sync.Mutex{}

type BPFWatchInfo bpfWatchInfoT

type Tracer struct {
	cfg        *pipe.Config
	metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	Service    *svc.ID
}

func New(cfg *pipe.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "watcher.Tracer")
	return &Tracer{
		log:     log,
		cfg:     cfg,
		metrics: metrics,
	}
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	return nil
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
		"security_socket_bind": {
			Required: true,
			Start:    p.bpfObjects.KprobeSecuritySocketBind,
		},
	}

	return kprobes
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) AllowPID(_ uint32) {
}

func (p *Tracer) BlockPID(_ uint32) {
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	p.Service = &service
	ebpfcommon.ForwardRingbuf[uint32](
		service,
		&p.cfg.EBPF, p.log, p.bpfObjects.WatchEvents,
		p.processWatchEvent,
		nil,
		p.metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}

func newPort() {
	mux.Lock()
	defer mux.Unlock()
	newPortOfInterest = true
}

func PortScanRequired() bool {
	mux.Lock()
	defer mux.Unlock()

	ret := newPortOfInterest
	newPortOfInterest = false

	return ret
}

func (p *Tracer) checkPort(port uint16) {
	p.log.Debug("Checking if we should track", "port", port)

	if p.cfg.Port.Matches(int(port)) || p.cfg.Discovery.Services.PortOfInterest(int(port)) {
		p.log.Debug("Found new port of interest", "port", port)
		newPort()
	}
}

func (p *Tracer) processWatchEvent(record *ringbuf.Record) (request.Span, bool, error) {
	var flags uint64
	var event BPFWatchInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flags)
	if err != nil {
		return request.Span{}, true, err
	}

	if flags == 1 { // socket bind
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

		if err == nil {
			p.checkPort(uint16(event.Payload))
		}
	}

	return request.Span{}, true, nil
}
