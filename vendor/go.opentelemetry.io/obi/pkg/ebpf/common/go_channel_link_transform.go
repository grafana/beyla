// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
)

const (
	maxPendingSpanLinks = 1024
	pendingSpanLinksTTL = 5 * time.Minute

	// TODO(#2283): Honor OTEL_SPAN_LINK_COUNT_LIMIT when constructing parser state.
	maxSpanLinks = sdktrace.DefaultLinkCountLimit
)

type spanLinkKey struct {
	traceID trace.TraceID
	spanID  trace.SpanID
}

type pendingSpanLinks struct {
	// Links are keyed by the receiver span that should receive them when it is parsed.
	cache *expirable.LRU[spanLinkKey, []request.SpanLink]
}

func newPendingSpanLinks() *pendingSpanLinks {
	return newPendingSpanLinksWith(maxPendingSpanLinks, pendingSpanLinksTTL)
}

func newPendingSpanLinksWith(size int, ttl time.Duration) *pendingSpanLinks {
	return &pendingSpanLinks{
		cache: expirable.NewLRU[spanLinkKey, []request.SpanLink](size, nil, ttl),
	}
}

func readGoChannelLinkEvent(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	if parseCtx == nil {
		return request.Span{}, true, nil
	}

	event, err := ReinterpretCast[GoChannelLinkTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	parseCtx.ensurePendingSpanLinks().recordLink(
		tpToSpanLinkKey(event.ReceiverTp.TraceId, event.ReceiverTp.SpanId),
		tpToSpanLink(event.SenderTp.TraceId, event.SenderTp.SpanId, event.SenderTp.Flags),
	)

	return request.Span{}, true, nil
}

func (ctx *EBPFParseContext) ensurePendingSpanLinks() *pendingSpanLinks {
	if ctx.pendingSpanLinks == nil {
		ctx.pendingSpanLinks = newPendingSpanLinks()
	}
	return ctx.pendingSpanLinks
}

func (ctx *EBPFParseContext) consumePendingSpanLinks(span *request.Span) {
	if ctx == nil || ctx.pendingSpanLinks == nil || span == nil {
		return
	}

	if !span.TraceID.IsValid() || !span.SpanID.IsValid() {
		return
	}

	ctx.pendingSpanLinks.consume(span)
}

func tpToSpanLinkKey(traceID [16]uint8, spanID [8]uint8) spanLinkKey {
	return spanLinkKey{
		traceID: trace.TraceID(traceID),
		spanID:  trace.SpanID(spanID),
	}
}

func tpToSpanLink(traceID [16]uint8, spanID [8]uint8, flags uint8) request.SpanLink {
	return request.SpanLink{
		TraceID:    trace.TraceID(traceID),
		SpanID:     trace.SpanID(spanID),
		TraceFlags: flags,
	}
}

func (p *pendingSpanLinks) recordLink(key spanLinkKey, link request.SpanLink) {
	if p == nil || p.cache == nil {
		return
	}

	if !key.traceID.IsValid() || !key.spanID.IsValid() || !link.TraceID.IsValid() || !link.SpanID.IsValid() {
		return
	}

	if key.traceID == link.TraceID && key.spanID == link.SpanID {
		return
	}

	links, _ := p.cache.Get(key)
	// OpenTelemetry does not require span links to be unique. OBI deduplicates
	// reconstructed channel links because these links currently carry only the
	// sender SpanContext. If link attributes later carry per-handoff details,
	// this normalization should be revisited.
	for _, existing := range links {
		if existing.TraceID == link.TraceID && existing.SpanID == link.SpanID {
			return
		}
	}

	if len(links) >= maxSpanLinks {
		return
	}

	links = append(links, link)
	p.cache.Add(key, links)
}

func (p *pendingSpanLinks) consume(span *request.Span) {
	if p == nil || p.cache == nil || span == nil {
		return
	}

	key := spanLinkKey{
		traceID: span.TraceID,
		spanID:  span.SpanID,
	}

	links, ok := p.cache.Get(key)
	if !ok || len(links) == 0 {
		return
	}

	for _, link := range links {
		if len(span.Links) >= maxSpanLinks {
			break
		}

		duplicate := false
		for _, existing := range span.Links {
			if existing.TraceID == link.TraceID && existing.SpanID == link.SpanID {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		span.Links = append(span.Links, link)
	}

	p.cache.Remove(key)
}
