// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly // import "go.opentelemetry.io/obi/pkg/appolly"

import (
	"container/list"
	"context"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// At the moment an instrumented process makes an outgoing call, eBPF cannot
// always tell whether the inbound request it would join is still being served:
// once a response has started, only its content says where it ends. Those
// children arrive marked ParentConditional and are held here until their
// parent span shows up carrying the request's real end timestamp. A child that
// started before the parent ended was part of serving it and keeps the link; a
// child that started afterwards was not, and is detached so finished requests
// stop parenting the process' later, unrelated calls.
//
// A parent that never arrives within the transaction bound leaves its children
// unprovable, and unprovable links are refused the same way.

const (
	// bounds memory, not correctness: on overflow the oldest held span is
	// settled as unproven
	maxHeldSpans = 8192
	// spans this stage has seen, for resolving children that arrive after
	// their parent
	seenSpanEnds = 65536

	settleTick = 500 * time.Millisecond
)

type spanKey struct {
	traceID [16]byte
	spanID  [8]byte
}

type heldSpan struct {
	span     request.Span
	deadline time.Time
}

type parentSettler struct {
	output *msg.Queue[[]request.Span]
	maxTx  time.Duration

	ends *lru.Cache[spanKey, int64]
	// held children by the parent they wait for; order tracks deadlines
	held  map[spanKey][]*list.Element
	order *list.List // of heldSpan
}

// SettleConditionalParents resolves conditionally-parented spans against their
// parent's end timestamp before anything downstream sees them.
func SettleConditionalParents(
	maxTx time.Duration,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		ends, err := lru.New[spanKey, int64](seenSpanEnds)
		if err != nil {
			return nil, err
		}

		s := &parentSettler{
			output: output,
			maxTx:  maxTx,
			ends:   ends,
			held:   map[spanKey][]*list.Element{},
			order:  list.New(),
		}
		in := input.Subscribe(msg.SubscriberName("appolly.SettleConditionalParents"))

		return s.run(in), nil
	}
}

func (s *parentSettler) run(in <-chan []request.Span) swarm.RunFunc {
	return func(ctx context.Context) {
		defer s.output.Close()

		ticker := time.NewTicker(settleTick)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.flush(ctx)
				return
			case spans, ok := <-in:
				if !ok {
					s.flush(ctx)
					return
				}
				s.process(ctx, spans)
			case now := <-ticker.C:
				s.expire(ctx, now)
			}
		}
	}
}

func (s *parentSettler) process(ctx context.Context, spans []request.Span) {
	out := make([]request.Span, 0, len(spans))

	for i := range spans {
		span := &spans[i]

		// every span is a potential parent for children that arrived first
		key := spanKey{traceID: span.TraceID, spanID: span.SpanID}
		s.ends.Add(key, span.End)
		out = append(out, s.release(key, span.End)...)

		if !span.ParentConditional || !span.ParentSpanID.IsValid() {
			out = append(out, *span)
			continue
		}

		parent := spanKey{traceID: span.TraceID, spanID: span.ParentSpanID}
		if end, ok := s.ends.Get(parent); ok {
			out = append(out, settle(*span, end))
			continue
		}

		s.hold(ctx, parent, *span)
	}

	if len(out) > 0 {
		s.output.SendCtx(ctx, out)
	}
}

// settle keeps the parent link only when the child started while the parent
// was still running
func settle(span request.Span, parentEnd int64) request.Span {
	if span.Start < parentEnd {
		return span
	}

	return detachParent(span)
}

// detachParent removes a stale parent without changing the trace identity that
// the span may already have propagated to downstream services.
func detachParent(span request.Span) request.Span {
	span.ParentSpanID = [8]byte{}

	return span
}

func (s *parentSettler) hold(ctx context.Context, parent spanKey, span request.Span) {
	// refusing the link is better than unbounded memory
	if s.order.Len() >= maxHeldSpans {
		s.expireOldest(ctx)
	}

	el := s.order.PushBack(heldSpan{span: span, deadline: time.Now().Add(s.maxTx)})
	s.held[parent] = append(s.held[parent], el)
}

func (s *parentSettler) release(parent spanKey, parentEnd int64) []request.Span {
	els := s.held[parent]
	if els == nil {
		return nil
	}
	delete(s.held, parent)

	out := make([]request.Span, 0, len(els))
	for _, el := range els {
		held, ok := s.order.Remove(el).(heldSpan)
		if !ok {
			continue
		}
		out = append(out, settle(held.span, parentEnd))
	}

	return out
}

func (s *parentSettler) expire(ctx context.Context, now time.Time) {
	var out []request.Span

	for front := s.order.Front(); front != nil; front = s.order.Front() {
		held, ok := front.Value.(heldSpan)
		if !ok || held.deadline.After(now) {
			break
		}
		out = append(out, s.removeHeld(front))
	}

	if len(out) > 0 {
		s.output.SendCtx(ctx, out)
	}
}

func (s *parentSettler) expireOldest(ctx context.Context) {
	front := s.order.Front()
	if front == nil {
		return
	}

	span := s.removeHeld(front)
	s.output.SendCtx(ctx, []request.Span{span})
}

// removeHeld drops the element from both indexes and settles it as unproven
func (s *parentSettler) removeHeld(el *list.Element) request.Span {
	held, _ := s.order.Remove(el).(heldSpan)

	parent := spanKey{traceID: held.span.TraceID, spanID: held.span.ParentSpanID}
	els := s.held[parent]
	for i, e := range els {
		if e == el {
			s.held[parent] = append(els[:i], els[i+1:]...)
			break
		}
	}
	if len(s.held[parent]) == 0 {
		delete(s.held, parent)
	}

	return detachParent(held.span)
}

// flush settles everything still held as unproven so no span is lost
func (s *parentSettler) flush(ctx context.Context) {
	var out []request.Span
	for front := s.order.Front(); front != nil; front = s.order.Front() {
		out = append(out, s.removeHeld(front))
	}

	if len(out) > 0 {
		s.output.SendCtx(ctx, out)
	}
}
