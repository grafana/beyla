package watcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/watcher"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/config"
	ebpfcommon "github.com/grafana/beyla/v2/pkg/internal/ebpf/common"
)

type BPFWatchInfo watcher.BpfWatchInfoT

type Watcher struct {
	cfg        *beyla.Config
	bpfObjects watcher.BpfObjects
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
	loader := watcher.LoadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = watcher.LoadBpfDebug
	}

	return loader()
}

func (p *Watcher) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Watcher) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Watcher) KProbes() map[string]ebpfcommon.ProbeDesc {
	kprobes := map[string]ebpfcommon.ProbeDesc{
		"sys_bind": {
			Required: true,
			Start:    p.bpfObjects.BeylaKprobeSysBind,
		},
	}

	return kprobes
}

func (p *Watcher) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return nil
}

func (p *Watcher) SetupTailCalls() {}

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

func (p *Watcher) processWatchEvent(_ *ebpfcommon.EBPFParseContext, _ *config.EBPFTracer, record *ringbuf.Record, _ ebpfcommon.ServiceFilter) (request.Span, bool, error) {
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
