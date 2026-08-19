// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package watcher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/watcher"

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type watch_info_t -target amd64,arm64 Bpf ../../../../bpf/watcher/watcher.c -- -I../../../../bpf

type BPFWatchInfo BpfWatchInfoT

type Watcher struct {
	cfg        *obi.Config
	bpfObjects BpfObjects
	closers    []io.Closer
	log        *slog.Logger
	events     chan<- Event
	forward    func(context.Context, watchEventParser)
}

type watchEventParser func(*ringbuf.Record) (request.Span, bool, error)

type EventType int

const (
	Ready = EventType(iota)
	NewPort
)

const watchBind uint64 = 1

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

func (p *Watcher) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Watcher) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
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
	parse := func(record *ringbuf.Record) (request.Span, bool, error) {
		return p.processWatchEvent(ctx, record)
	}
	_ = p.sendEvent(ctx, Event{Type: Ready})
	if p.forward != nil {
		p.forward(ctx, parse)
		return
	}
	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.WatchEvents,
		parse,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)
}

func (p *Watcher) sendEvent(ctx context.Context, event Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Watcher) processWatchEvent(ctx context.Context, record *ringbuf.Record) (request.Span, bool, error) {
	var flags uint64
	var event BPFWatchInfo

	err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &flags)
	if err != nil {
		return request.Span{}, true, err
	}

	if flags == watchBind { // socket bind
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			return request.Span{}, true, err
		}

		p.log.Debug("New port bind event", "port", event.Payload)
		if err := p.sendEvent(ctx, Event{Type: NewPort, Payload: uint32(event.Payload)}); err != nil {
			return request.Span{}, true, err
		}
	}

	return request.Span{}, true, nil
}
