package otel

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"

	"go.opentelemetry.io/otel/trace"
)

type BeylaIDGenerator struct{}
type traceAndSpanKey struct{}
type traceOnlyKey struct{}

type idPair struct {
	traceID trace.TraceID
	spanID  trace.SpanID
}

func ContextWithTraceParent(parent context.Context, traceID trace.TraceID, spanID trace.SpanID) context.Context {
	return context.WithValue(parent, traceAndSpanKey{}, idPair{traceID: traceID, spanID: spanID})
}

func ContextWithTrace(parent context.Context, traceID trace.TraceID) context.Context {
	return context.WithValue(parent, traceOnlyKey{}, traceID)
}

func currentTraceAndSpan(ctx context.Context) *idPair {
	val := ctx.Value(traceAndSpanKey{})
	if val == nil {
		return nil
	}

	holder, ok := val.(idPair)
	if !ok {
		return nil
	}

	return &holder
}

func currentTrace(ctx context.Context) *trace.TraceID {
	val := ctx.Value(traceOnlyKey{})
	if val == nil {
		return nil
	}

	holder, ok := val.(trace.TraceID)
	if !ok {
		return nil
	}

	return &holder
}

func randomTraceID() trace.TraceID {
	t := trace.TraceID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func randomSpanID() trace.SpanID {
	t := trace.SpanID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func (e *BeylaIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	pair := currentTraceAndSpan(ctx)
	if pair == nil || !trace.TraceID(pair.traceID).IsValid() || !trace.SpanID(pair.spanID).IsValid() {
		traceID := currentTrace(ctx)
		if traceID != nil {
			return *traceID, randomSpanID()
		}
		fmt.Println("BAD BAD BAD")
		return randomTraceID(), randomSpanID()
	}

	return trace.TraceID(pair.traceID), trace.SpanID(pair.spanID)
}

func (e *BeylaIDGenerator) NewSpanID(ctx context.Context, traceID trace.TraceID) trace.SpanID {
	pair := currentTraceAndSpan(ctx)
	if pair == nil || !trace.SpanID(pair.spanID).IsValid() {
		fmt.Printf("I'm getting new random SpanID, this is OK\n")
		return randomSpanID()
	}

	return trace.SpanID(pair.spanID)
}
