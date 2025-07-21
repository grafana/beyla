// Copyright The OpenTelemetry Authors
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation was inspired by the code in
// https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/cdfad4a67b86c282ed29141ca0b3bca46509eee9/internal/pkg/opentelemetry/id_generator.go

package otel

import (
	"context"
	"encoding/binary"
	"math/rand/v2"

	"go.opentelemetry.io/otel/trace"
)

type (
	BeylaIDGenerator struct{}
	traceAndSpanKey  struct{}
	traceOnlyKey     struct{}
)

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

func RandomTraceID() trace.TraceID {
	t := trace.TraceID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func RandomSpanID() trace.SpanID {
	t := trace.SpanID{}

	for i := 0; i < len(t); i += 4 {
		binary.LittleEndian.PutUint32(t[i:], rand.Uint32())
	}

	return t
}

func (e *BeylaIDGenerator) NewIDs(ctx context.Context) (trace.TraceID, trace.SpanID) {
	pair := currentTraceAndSpan(ctx)
	if pair == nil || !pair.traceID.IsValid() || !pair.spanID.IsValid() {
		traceID := currentTrace(ctx)
		if traceID != nil {
			return *traceID, RandomSpanID()
		}
		return RandomTraceID(), RandomSpanID()
	}

	return pair.traceID, pair.spanID
}

func (e *BeylaIDGenerator) NewSpanID(ctx context.Context, _ trace.TraceID) trace.SpanID {
	pair := currentTraceAndSpan(ctx)
	if pair == nil || !pair.spanID.IsValid() {
		return RandomSpanID()
	}

	return pair.spanID
}
