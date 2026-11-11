// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package customspan // import "go.opentelemetry.io/obi/pkg/internal/ebpf/customspan"

import (
	"errors"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
)

// CustomSpanDef binds a config span to its runtime cookie and the per-arg
// attribute layout used to decode incoming events. Pair-key source is
// carried per-event via CustomSpanRawEvent.PairKind, not stored here.
type CustomSpanDef struct {
	Cookie     uint64
	Name       string
	IsPair     bool
	ProbeID    string
	Generation uint64
	usedSlots  []customSpanAttrSlot
}

type customSpanAttrSlot struct {
	Return bool
	ArgIdx uint8
	Name   string
	Type   config.CustomSpanAttrType
	Auto   bool
}

func NewCustomSpanDef(span *config.CustomSpanSpec, cookie uint64) *CustomSpanDef {
	def := &CustomSpanDef{
		Cookie: cookie,
		Name:   span.Name,
		IsPair: span.IsUSDTSpan() || span.IsFunctionSpan(),
	}
	for name, a := range span.Attrs {
		if int(a.Arg) >= customSpanMaxArgs {
			continue
		}
		def.usedSlots = append(def.usedSlots, customSpanAttrSlot{
			ArgIdx: a.Arg,
			Name:   name,
			Type:   a.Type,
		})
	}
	return def
}

// CustomSpanRegistry resolves an event cookie back to its CustomSpanDef.
type CustomSpanRegistry struct {
	mu   sync.RWMutex
	defs map[uint64]*CustomSpanDef
}

func NewCustomSpanRegistry() *CustomSpanRegistry {
	return &CustomSpanRegistry{defs: map[uint64]*CustomSpanDef{}}
}

func (r *CustomSpanRegistry) Register(def *CustomSpanDef) {
	r.mu.Lock()
	r.defs[def.Cookie] = def
	r.mu.Unlock()
}

func (r *CustomSpanRegistry) Remove(cookie uint64) {
	r.mu.Lock()
	delete(r.defs, cookie)
	r.mu.Unlock()
}

// SetAutoSlots replaces auto slots on def; manual slots preserved.
func (r *CustomSpanRegistry) SetAutoSlots(cookie uint64, slots []obiebpf.AutoAttrSlot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	def, ok := r.defs[cookie]
	if !ok {
		return
	}
	copyDef := *def
	def = &copyDef
	kept := make([]customSpanAttrSlot, 0, len(def.usedSlots))
	for _, s := range def.usedSlots {
		if !s.Auto {
			kept = append(kept, s)
		}
	}
	def.usedSlots = kept
	for _, s := range slots {
		def.usedSlots = append(def.usedSlots, customSpanAttrSlot{
			ArgIdx: s.ArgIdx,
			Name:   s.Name,
			Type:   s.Type,
			Auto:   true,
			Return: s.Return,
		})
	}
	r.defs[cookie] = def
}

func (r *CustomSpanRegistry) Lookup(cookie uint64) (*CustomSpanDef, bool) {
	r.mu.RLock()
	d, ok := r.defs[cookie]
	r.mu.RUnlock()
	return d, ok
}

// customSpanPairKey indexes the userspace pairing map. Pair-key source is
// driven by ev.PairKind which mirrors spec.pair_kind: arg_int[0] for USDT
// paired (the correlation-key convention), GlobalTid for C function_span,
// GPtr (Go runtime g*) for Go function_span — TID is unstable on Go since
// the scheduler moves goroutines between OS threads at every blocking call.
type customSpanPairKey struct {
	Kind   uint8
	PID    uint32
	Cookie uint64
	Key    uint64
}

func makePairKey(_ *CustomSpanDef, ev *CustomSpanRawEvent) customSpanPairKey {
	k := customSpanPairKey{PID: ev.GlobalPid, Cookie: ev.Cookie, Kind: ev.PairKind}
	switch ev.PairKind {
	case 1: // obiUSDTPairTid
		k.Key = uint64(ev.GlobalTid)
	case 2, 3: // Go goroutine or Java invocation ID
		k.Key = ev.GPtr
	default: // obiUSDTPairArg0
		k.Key = ev.ArgInt[0]
	}
	return k
}

type customSpanPending struct {
	KernelContext bool
	TraceFlags    uint8
	StackOffset   uint32
	ID            trace.SpanID
	ContextSpanID trace.SpanID
	Cookie        uint64
	StartedAt     time.Time
	StartTimeNs   uint64
	Attrs         map[string]string
	HasTraceCtx   bool
	TraceID       trace.TraceID
	SpanID        trace.SpanID
	GlobalPid     uint32
	GlobalTid     uint32
	NsPid         uint32
	NsTid         uint32
	PidNsID       uint32
}

// CustomSpanPairer correlates start/end events by (pid, cookie, arg0) and ages
// out stale starts after TTL.
type CustomSpanPairer struct {
	now     func() time.Time
	ttl     time.Duration
	mu      sync.Mutex
	pending map[customSpanPairKey][]customSpanPending
	parents *simplelru.LRU[customSpanPairKey, customSpanParent]
}

func NewCustomSpanPairer(ttl time.Duration) *CustomSpanPairer {
	parents, _ := simplelru.NewLRU[customSpanPairKey, customSpanParent](maxCustomSpanGoroutines, nil)
	return &CustomSpanPairer{
		now:     time.Now,
		ttl:     ttl,
		pending: map[customSpanPairKey][]customSpanPending{},
		parents: parents,
	}
}

func (p *CustomSpanPairer) putStart(key customSpanPairKey, pending customSpanPending) {
	p.mu.Lock()
	pending.Cookie = key.Cookie
	if key.Kind != 0 {
		key.Cookie = 0
	}
	stack := p.pending[key]
	if key.Kind == obiebpf.ObiUSDTPairG() && pending.StackOffset != 0 {
		// Stack growth retries an entry at the same depth; unwinding can also leave stale deeper frames.
		for len(stack) > 0 && stack[len(stack)-1].StackOffset >= pending.StackOffset {
			stack = stack[:len(stack)-1]
		}
	}
	if parent, ok := p.parentContextLocked(key, stack); ok && !pending.KernelContext {
		pending.inherit(parent)
	}
	if !pending.TraceID.IsValid() {
		pending.TraceID = idgen.RandomTraceID()
	}
	p.pending[key] = append(stack, pending)
	p.mu.Unlock()
}

func (p *CustomSpanPairer) takeStart(key customSpanPairKey, id trace.SpanID) (customSpanPending, bool) {
	p.mu.Lock()
	cookie := key.Cookie
	if key.Kind != 0 {
		key.Cookie = 0
	}
	stack := p.pending[key]
	for i, value := range slices.Backward(stack) {
		if value.Cookie != cookie || (value.KernelContext && value.ID != id) {
			continue
		}

		stack = stack[:i]
		if len(stack) == 0 {
			delete(p.pending, key)
		} else {
			p.pending[key] = stack
		}
		p.mu.Unlock()
		return value, true
	}
	p.mu.Unlock()
	return customSpanPending{}, false
}

func (p *CustomSpanPairer) Remove(cookie uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, key := range p.parents.Keys() {
		if parent, _ := p.parents.Peek(key); parent.Cookie == cookie {
			p.parents.Remove(key)
			delete(p.pending, key)
		}
	}
	for key, stack := range p.pending {
		for i, frame := range stack {
			if frame.Cookie == cookie {
				// Descendants refer to this span and cannot be completed after it is removed.
				stack = stack[:i]
				break
			}
		}
		if len(stack) == 0 {
			delete(p.pending, key)
		} else {
			p.pending[key] = stack
		}
	}
}

// EvictExpired removes incomplete calls and inherited context older than TTL.
// Caller invokes this periodically; the package does not own a goroutine.
func (p *CustomSpanPairer) EvictExpired() int {
	cutoff := p.now().Add(-p.ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, key := range p.parents.Keys() {
		if parent, _ := p.parents.Peek(key); parent.StartedAt.Before(cutoff) {
			p.parents.Remove(key)
			n++
		}
	}
	for k, v := range p.pending {
		if len(v) > 0 && v[0].StartedAt.Before(cutoff) {
			delete(p.pending, k)
			n++
		}
	}
	return n
}

// PendingLen returns the size of the in-flight map.
func (p *CustomSpanPairer) PendingLen() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, stack := range p.pending {
		n += len(stack)
	}
	return n
}

// Builder turns BPF events into request.Span instances.
type CustomSpanBuilder struct {
	reg    *CustomSpanRegistry
	pairer *CustomSpanPairer
}

func NewCustomSpanBuilder(reg *CustomSpanRegistry, pairer *CustomSpanPairer) *CustomSpanBuilder {
	return &CustomSpanBuilder{reg: reg, pairer: pairer}
}

// Build consumes one decoded event. It returns (span, true, nil) when a span
// is ready to emit (end-of-pair or single-shot), (zero, false, nil) when the
// event was buffered as a pending start, or (zero, false, err) on bad input.
// Unknown cookies / unknown event kinds resolve to (zero, false, nil).
func (b *CustomSpanBuilder) Build(ev *CustomSpanRawEvent) (request.Span, bool, error) {
	if ev == nil {
		return request.Span{}, false, errors.New("custom_span: nil event")
	}
	def, ok := b.reg.Lookup(ev.Cookie)
	if !ok {
		return request.Span{}, false, nil
	}

	switch ev.Kind {
	case uint8(obiebpf.CustomSpanKindStart):
		if !def.IsPair {
			return request.Span{}, false, nil
		}
		b.pairer.putStart(makePairKey(def, ev), b.newPending(def, ev))
		return request.Span{}, false, nil

	case uint8(obiebpf.CustomSpanKindEnd):
		if !def.IsPair {
			return request.Span{}, false, nil
		}
		pending, found := b.pairer.takeStart(makePairKey(def, ev), trace.SpanID(ev.ID))
		if !found {
			return request.Span{}, false, nil
		}
		return composeSpan(def, &pending, ev, ev.Timestamp), true, nil

	case uint8(obiebpf.CustomSpanKindSingle):
		if def.IsPair {
			return request.Span{}, false, nil
		}
		key := makePairKey(def, ev)
		b.pairer.putStart(key, b.newPending(def, ev))
		pending, _ := b.pairer.takeStart(key, trace.SpanID(ev.ID))
		return composeSpan(def, &pending, ev, ev.Timestamp), true, nil
	}
	return request.Span{}, false, nil
}

func (b *CustomSpanBuilder) newPending(def *CustomSpanDef, ev *CustomSpanRawEvent) customSpanPending {
	id := trace.SpanID(ev.ID)
	kernelContext := id.IsValid()
	if !kernelContext {
		id = idgen.RandomSpanID()
	}
	return customSpanPending{
		ID:            id,
		KernelContext: kernelContext,
		TraceFlags:    ev.TraceFlags,
		StackOffset:   ev.StackOffset,
		StartedAt:     b.pairer.now(),
		StartTimeNs:   ev.Timestamp,
		Attrs:         extractAttrs(def, ev),
		HasTraceCtx:   ev.HasTraceCtx != 0,
		TraceID:       trace.TraceID(ev.TraceID),
		SpanID:        trace.SpanID(ev.SpanID),
		ContextSpanID: trace.SpanID(ev.SpanID),
		GlobalPid:     ev.GlobalPid,
		GlobalTid:     ev.GlobalTid,
		NsPid:         ev.NsPid,
		NsTid:         ev.NsTid,
		PidNsID:       ev.PidNsID,
	}
}

func extractAttrs(def *CustomSpanDef, ev *CustomSpanRawEvent) map[string]string {
	out := make(map[string]string, len(def.usedSlots)+2)
	applyAttrs(def, ev, out)
	if def.ProbeID != "" {
		out["probe.id"] = def.ProbeID
		out["probe.generation"] = strconv.FormatUint(def.Generation, 10)
	}
	return out
}

// applyAttrs writes each used slot into out when the event's wire kind agrees
// with the declared type. The kind gate prevents a paired probe whose
// start/end arg layouts diverge from poisoning the span with garbage.
func applyAttrs(def *CustomSpanDef, ev *CustomSpanRawEvent, out map[string]string) {
	for _, slot := range def.usedSlots {
		if ev.PairKind != 0 && slot.Return != (ev.Kind == uint8(obiebpf.CustomSpanKindEnd)) {
			continue
		}
		i := slot.ArgIdx
		kind := ev.ArgKind[i]
		switch {
		case slot.Type.IsString() && kind == uint8(obiebpf.CustomSpanArgStr):
			out[slot.Name] = TrimNUL(ev.ArgStr[i][:], ev.ArgStrLen[i])
		case !slot.Type.IsString() && kind == uint8(obiebpf.CustomSpanArgInt):
			// Empty Type (USDT int auto-derived) → format as unsigned u64.
			signed := slot.Type.Signed()
			width := int(slot.Type.SizeBytes())
			if width == 0 {
				width = 8
			}
			out[slot.Name] = FormatArgInt(ev.ArgInt[i], obiebpf.CustomSpanArgInt, signed, width)
		}
	}
}

func composeSpan(def *CustomSpanDef, pending *customSpanPending, ev *CustomSpanRawEvent, endNs uint64) request.Span {
	attrs := pending.Attrs
	if def.IsPair {
		// Overlay end-side attrs (e.g. status code) onto the start map.
		applyAttrs(def, ev, attrs)
	}
	span := request.Span{
		Type:         request.EventTypeCustomSpan,
		SpanID:       pending.ID,
		TraceID:      pending.TraceID,
		TraceFlags:   pending.TraceFlags,
		Method:       def.Name,
		RequestStart: int64(pending.StartTimeNs),
		Start:        int64(pending.StartTimeNs),
		End:          int64(endNs),
		Pid: request.PidInfo{
			HostPID:   app.PID(pending.GlobalPid),
			UserPID:   app.PID(pending.NsPid),
			Namespace: pending.PidNsID,
		},
		CustomSpan: &request.CustomSpan{
			Name:  def.Name,
			Attrs: attrs,
		},
	}
	if pending.HasTraceCtx {
		span.TraceID = pending.TraceID
		span.ParentSpanID = pending.SpanID
	}
	return span
}
