// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"bytes"
	"encoding/binary"
	"time"

	"go.opentelemetry.io/otel/trace"

	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
)

const (
	customSpanGoroutineStart = 1
	customSpanGoroutineEnd   = 2
	maxCustomSpanGoroutines  = 30000
)

// Mirrors go_dynamic_goroutine_event in bpf/gotracer/go_dynamic_goroutines.h.
type customSpanGoroutineEvent struct {
	Type      uint8
	Kind      uint8
	_         [2]byte
	PID       uint32
	Goroutine uint64
	Parent    uint64
	TraceID   trace.TraceID
	SpanID    trace.SpanID
}

func decodeCustomSpanGoroutineEvent(raw []byte) (customSpanGoroutineEvent, error) {
	var event customSpanGoroutineEvent
	err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &event)
	return event, err
}

type customSpanParent struct {
	ID            trace.SpanID
	TraceID       trace.TraceID
	ContextSpanID trace.SpanID
	Cookie        uint64
	StartedAt     time.Time
}

func (p *customSpanPending) inherit(parent customSpanParent) bool {
	if !parent.TraceID.IsValid() || !parent.ID.IsValid() {
		return false
	}
	if p.TraceID.IsValid() && (p.TraceID != parent.TraceID || p.ContextSpanID != parent.ContextSpanID) {
		return false
	}
	p.TraceID = parent.TraceID
	p.SpanID = parent.ID
	p.ContextSpanID = parent.ContextSpanID
	p.HasTraceCtx = true
	return true
}

func (p *CustomSpanPairer) parentContextLocked(key customSpanPairKey, stack []customSpanPending) (customSpanParent, bool) {
	if len(stack) > 0 {
		parent := stack[len(stack)-1]
		return customSpanParent{ID: parent.ID, TraceID: parent.TraceID, ContextSpanID: parent.ContextSpanID, Cookie: parent.Cookie, StartedAt: parent.StartedAt}, true
	}
	parent, ok := p.parents.Get(key)
	if ok && parent.StartedAt.Before(p.now().Add(-p.ttl)) {
		p.parents.Remove(key)
		return customSpanParent{}, false
	}
	return parent, ok
}

func (p *CustomSpanPairer) observeGoroutine(event customSpanGoroutineEvent) {
	if event.Kind != customSpanGoroutineStart && event.Kind != customSpanGoroutineEnd {
		return
	}
	key := customSpanPairKey{PID: event.PID, Kind: obiebpf.ObiUSDTPairG(), Key: event.Goroutine}
	p.mu.Lock()
	defer p.mu.Unlock()
	// Go reuses goroutine objects; neither pending calls nor inherited context survives reuse.
	delete(p.pending, key)
	p.parents.Remove(key)
	if event.Kind == customSpanGoroutineEnd || event.Parent == 0 || event.Parent == event.Goroutine {
		return
	}

	parentKey := customSpanPairKey{PID: event.PID, Kind: obiebpf.ObiUSDTPairG(), Key: event.Parent}
	context := customSpanPending{TraceID: event.TraceID, SpanID: event.SpanID, ContextSpanID: event.SpanID}
	if parent, ok := p.parentContextLocked(parentKey, p.pending[parentKey]); ok && context.inherit(parent) {
		context.Cookie = parent.Cookie
	}
	if context.TraceID.IsValid() && context.SpanID.IsValid() {
		p.parents.Add(key, customSpanParent{ID: context.SpanID, TraceID: context.TraceID, ContextSpanID: context.ContextSpanID, Cookie: context.Cookie, StartedAt: p.now()})
	}
}
