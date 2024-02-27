package grafanaagent

import (
	"context"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

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

				t := span.Timings()
				parentCtx := otel.HandleTraceparent(ctx, span)
				realStart := otel.SpanStartTime(t)
				hasSubSpans := t.Start.After(realStart)
				if !hasSubSpans {
					// We set the eBPF calculated trace_id and span_id to be the main span
					parentCtx = otel.ContextWithTraceParent(parentCtx, span.TraceID, span.SpanID)
				}
				for _, tc := range cfg.Traces {
					err := tc.ConsumeTraces(parentCtx, generateTraces(span, t, realStart, hasSubSpans))
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}

// generateTraces creates a pdata.Traces from a request.Span
func generateTraces(span *request.Span, t request.Timings, start time.Time, hasSubSpans bool) ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	if hasSubSpans {
		createSubSpans(&ss, t)
	}

	// Create a parent span for the whole request session
	s := ss.Spans().AppendEmpty()
	s.SetName(otel.TraceName(span))
	s.SetKind(ptrace.SpanKind(otel.SpanKind(span)))
	s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

	// Set span attributes
	attrs := otel.TraceAttributes(span)
	m := attrsToMap(attrs)
	m.CopyTo(s.Attributes())

	// Set status code
	statusCode := codeToStatusCode(otel.SpanStatusCode(span))
	s.Status().SetCode(statusCode)
	s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	return traces
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(ss *ptrace.ScopeSpans, t request.Timings) {
	// Create a child span showing the queue time
	spQ := ss.Spans().AppendEmpty()
	spQ.SetName("in queue")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(t.RequestStart))
	spQ.SetKind(ptrace.SpanKindInternal)
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(t.Start))

	// Create a child span showing the processing time
	// Override the active context for the span to be the processing span
	// The trace_id and span_id from eBPF are attached here
	spP := ss.Spans().AppendEmpty()
	spP.SetName("processing")
	spP.SetStartTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spP.SetKind(ptrace.SpanKindInternal)
	spP.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
}

// attrsToMap converts a slice of attribute.KeyValue to a pcommon.Map
func attrsToMap(attrs []attribute.KeyValue) pcommon.Map {
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
