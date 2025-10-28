// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 Bpf ../../../../bpf/watcher/watcher.c -- -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 BpfDebug ../../../../bpf/watcher/watcher.c -- -I../../../../bpf -DBPF_DEBUG

type BPFWatchInfo BpfWatchInfoT

type Watcher struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
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

func New(cfg *obi.Config, events chan<- Event) *Watcher {
	log := slog.With("component", "watcher.Tracer")
	return &Watcher{
		log:    log,
		events: events,
		cfg:    cfg,
	}
}

func (p *Watcher) Load() (*ebpf.CollectionSpec, error) {
	loader := LoadBpf
	if p.cfg.EBPF.BpfDebug {
		loader = LoadBpfDebug
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
			Start:    p.bpfObjects.ObiKprobeSysBind,
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
