// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

// Runtime shares definitions and pairing state across readers of the global event ring buffer.
type Runtime struct {
	registry    *CustomSpanRegistry
	pairer      *CustomSpanPairer
	builder     *CustomSpanBuilder
	specManager *ebpfcommon.USDTSpecManager
	ttl         time.Duration
	log         *slog.Logger
}

func New(ttl time.Duration, eventContext *ebpfcommon.EBPFEventContext, log *slog.Logger) *Runtime {
	create := func() any {
		registry := NewCustomSpanRegistry()
		pairer := NewCustomSpanPairer(ttl)
		return &Runtime{
			registry:    registry,
			pairer:      pairer,
			builder:     NewCustomSpanBuilder(registry, pairer),
			specManager: &ebpfcommon.USDTSpecManager{},
			ttl:         ttl,
			log:         log,
		}
	}
	if eventContext == nil {
		return create().(*Runtime)
	}
	runtime := eventContext.DynamicSpanState(func() any {
		state := create().(*Runtime)
		state.specManager = &eventContext.CustomSpanSpecMgr
		return state
	}).(*Runtime)
	eventContext.SetCustomSpanHandler(runtime.HandleRecord)
	return runtime
}

func (r *Runtime) Register(span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) {
	def := NewCustomSpanDef(span, cookie)
	def.ProbeID = id
	def.Generation = generation
	r.registry.Register(def)
}

func (r *Runtime) Remove(cookie uint64) {
	if r != nil {
		r.registry.Remove(cookie)
		r.pairer.Remove(cookie)
	}
}

// HandleRecord returns (span, ready, handled, err) for dynamic
// instrumentation records, including goroutine lifecycle events.
func (r *Runtime) HandleRecord(record *ringbuf.Record) (request.Span, bool, bool, error) {
	if r == nil || record == nil || len(record.RawSample) == 0 {
		return request.Span{}, false, false, nil
	}
	if record.RawSample[0] == ebpfcommon.EventTypeNodeDynamicSpan {
		return r.readNodeSpan(record)
	}
	if record.RawSample[0] == ebpfcommon.EventTypeGoDynamicGoroutine {
		event, err := decodeCustomSpanGoroutineEvent(record.RawSample)
		if err == nil {
			r.pairer.observeGoroutine(event)
		}
		return request.Span{}, false, true, err
	}
	if record.RawSample[0] != ebpfcommon.EventTypeCustomSpan {
		return request.Span{}, false, false, nil
	}

	ev, err := DecodeCustomSpanEvent(record.RawSample)
	if err != nil {
		r.log.Debug("custom_span: decode failed", "error", err)
		return request.Span{}, false, true, nil
	}
	span, ready, err := r.builder.Build(ev)
	if err != nil {
		r.log.Debug("custom_span: build failed", "error", err)
		return request.Span{}, false, true, nil
	}
	return span, ready, true, nil
}

// Run expires incomplete calls and inherited goroutine context.
func (r *Runtime) Run(ctx context.Context) {
	if r == nil {
		return
	}
	interval := max(r.ttl/4, 10*time.Second)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := r.pairer.EvictExpired(); n > 0 {
				r.log.Debug("custom_span: evicted stale calls and goroutine contexts", "count", n)
			}
		}
	}
}

func (r *Runtime) RegisterJava(span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) {
	r.RegisterStringArgs(span, cookie, id, generation)
}

func (r *Runtime) RegisterStringArgs(span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) {
	r.Register(span, cookie, id, generation)
	var slots []obiebpf.AutoAttrSlot
	for i := range config.CustomSpanMaxArgs {
		slots = append(slots, obiebpf.AutoAttrSlot{ArgIdx: uint8(i), Name: fmt.Sprintf("arg%d", i), Type: config.CustomSpanAttrString})
	}
	slots = append(slots, obiebpf.AutoAttrSlot{ArgIdx: 0, Name: "return0", Type: config.CustomSpanAttrString, Return: true},
		obiebpf.AutoAttrSlot{ArgIdx: 1, Name: "exception.message", Type: config.CustomSpanAttrString, Return: true})
	r.registry.SetAutoSlots(cookie, slots)
}
