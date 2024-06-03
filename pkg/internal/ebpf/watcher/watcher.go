package watcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/beyla"
	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/request"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 bpf ../../../../bpf/watch_helper.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 bpf_debug ../../../../bpf/watch_helper.c -- -I../../../../bpf/headers -DBPF_DEBUG

type BPFWatchInfo bpfWatchInfoT

type Watcher struct {
	cfg        *beyla.Config
	bpfObjects bpfObjects
	closers    []io.Closer
	log        *slog.Logger
	events     chan<- Event
}

type EventType int

const (
	Ready = EventType(iota)
	NewPort
)

type Event struct {
	Type    EventType
	Payload uint32 // this will be either port or pid
}

func New(cfg *beyla.Config, events chan<- Event) *Watcher {
	log := slog.With("component", "watcher.Tracer")
	return &Watcher{
		log:    log,
		events: events,
		cfg:    cfg,
	}
}

func (p *Watcher) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = loadBpf_debug
	}

	return loader()
}

func (p *Watcher) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Watcher) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Watcher) KProbes() map[string]ebpfcommon.FunctionPrograms {
	kprobes := map[string]ebpfcommon.FunctionPrograms{
		"sys_bind": {
			Required: true,
			Start:    p.bpfObjects.KprobeSysBind,
		},
	}

	return kprobes
}

func (p *Watcher) Tracepoints() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Watcher) Run(ctx context.Context) {
	p.events <- Event{Type: Ready}
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.WatchEvents,
		&ebpfcommon.IdentityPidsFilter{},
		p.processWatchEvent,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func (p *Watcher) processWatchEvent(record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
	var flags uint64
	var event BPFWatchInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flags)
	if err != nil {
		return request.Span{}, true, err
	}

	if flags == 1 { // socket bind
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

		if err == nil {
			p.log.Debug("New port bind event", "port", event.Payload)
			p.events <- Event{Type: NewPort, Payload: uint32(event.Payload)}
		}
	}

	return request.Span{}, true, nil
}
