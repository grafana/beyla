package grafanaagent

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(ctx context.Context, cfg beyla.TracesReceiverConfig) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}

				for _, tc := range cfg.Traces {
					traces := generateTraces(ctx, span)
					err := tc.ConsumeTraces(ctx, traces)
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}

// generateTraces creates a ptrace.Traces from a request.Span
func generateTraces(ctx context.Context, span *request.Span) ptrace.Traces {
	idGen := &otel.BeylaIDGenerator{}
	t := span.Timings()
	start := otel.SpanStartTime(t)
	hasSubSpans := t.Start.After(start)

	parentCtx := otel.HandleTraceparent(ctx, span)
	if !hasSubSpans {
		// We set the eBPF calculated trace_id and span_id to be the main span
		parentCtx = otel.ContextWithTraceParent(parentCtx, span.TraceID, span.SpanID)
	}

	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	resourceAttrs := AttrsToMap(otel.Resource(span.ServiceID).Attributes())
	resourceAttrs.CopyTo(rs.Resource().Attributes())

	if hasSubSpans {
		createSubSpans(parentCtx, span, &ss, t, idGen)
	}

	// Create a parent span for the whole request session
	s := ss.Spans().AppendEmpty()
	s.SetName(otel.TraceName(span))
	s.SetKind(ptrace.SpanKind(otel.SpanKind(span)))
	s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

	// Set trace and span IDs
	setIds(parentCtx, &s, span.TraceID, span.ParentSpanID, idGen)

	// Set span attributes
	attrs := otel.TraceAttributes(span)
	m := AttrsToMap(attrs)
	m.CopyTo(s.Attributes())

	// Set status code
	statusCode := codeToStatusCode(otel.SpanStatusCode(span))
	s.Status().SetCode(statusCode)
	s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	return traces
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(ctx context.Context, span *request.Span, ss *ptrace.ScopeSpans, t request.Timings, idGen *otel.BeylaIDGenerator) {
	// Create a child span showing the queue time
	spQ := ss.Spans().AppendEmpty()
	spQ.SetName("in queue")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(t.RequestStart))
	spQ.SetKind(ptrace.SpanKindInternal)
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(t.Start))
	setIds(ctx, &spQ, span.TraceID, span.ParentSpanID, idGen)

	// Create a child span showing the processing time
	spP := ss.Spans().AppendEmpty()
	spP.SetName("processing")
	spP.SetStartTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spP.SetKind(ptrace.SpanKindInternal)
	spP.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	ctx = otel.ContextWithTraceParent(ctx, span.TraceID, span.SpanID)
	setIds(ctx, &spP, span.TraceID, span.ParentSpanID, idGen)
}

func setIds(ctx context.Context, s *ptrace.Span, traceID trace.TraceID, parentSpanID trace.SpanID, idGen *otel.BeylaIDGenerator) {
	var spanID trace.SpanID
	if !traceID.IsValid() {
		traceID, spanID = idGen.NewIDs(ctx)
	} else {
		spanID = idGen.NewSpanID(ctx, traceID)
	}
	if parentSpanID.IsValid() {
		s.SetSpanID(pcommon.SpanID(parentSpanID))
	} else {
		s.SetSpanID(pcommon.SpanID(spanID))
	}
	s.SetTraceID(pcommon.TraceID(traceID))
}

// AttrsToMap converts a slice of attribute.KeyValue to a pcommon.Map
func AttrsToMap(attrs []attribute.KeyValue) pcommon.Map {
	m := pcommon.NewMap()
	for _, attr := range attrs {
		switch v := attr.Value.AsInterface().(type) {
		case string:
			m.PutStr(string(attr.Key), v)
		case int64:
			m.PutInt(string(attr.Key), v)
		case float64:
			m.PutDouble(string(attr.Key), v)
		case bool:
			m.PutBool(string(attr.Key), v)
		}
	}
	return m
}

// codeToStatusCode converts a codes.Code to a ptrace.StatusCode
func codeToStatusCode(code codes.Code) ptrace.StatusCode {
	switch code {
	case codes.Unset:
		return ptrace.StatusCodeUnset
	case codes.Error:
		return ptrace.StatusCodeError
	case codes.Ok:
		return ptrace.StatusCodeOk
	}
	return ptrace.StatusCodeUnset
}
