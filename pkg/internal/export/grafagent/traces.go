package grafagent

import (
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/codes"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

func TracesExporterProvider(cfg beyla.TracesExporterConfig) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		for spans := range in {
			for _, span := range spans {
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}

				t := span.Timings()
				parentCtx := otel.HandleTraceparent(cfg.Context, &span)
				realStart := otel.SpanStartTime(t)
				hasSubspans := t.Start.After(realStart)
				if !hasSubspans {
					// We set the eBPF calculated trace_id and span_id to be the main span
					parentCtx = otel.ContextWithTraceParent(parentCtx, span.TraceID, span.SpanID)
				}
				for _, c := range cfg.Consumers {
					c.ConsumeTraces(parentCtx, generateTraces(span, t, realStart, hasSubspans))
				}
			}
		}
	}, nil
}

// generateTraces creates a pdata.Traces from a request.Span
func generateTraces(span request.Span, t request.Timings, start time.Time, hasSubspans bool) ptrace.Traces {
	traces := ptrace.NewTraces()

	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()

	// Create a parent span for the whole request session
	s := ss.Spans().AppendEmpty()
	s.SetName(otel.TraceName(&span))
	s.SetKind(ptrace.SpanKind(otel.SpanKind(&span)))
	s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
	res := rs.Resource()
	attrs := otel.TraceAttributes(&span)
	for _, kv := range attrs {
		res.Attributes().PutStr(string(kv.Key), kv.Value.AsString())
		s.Attributes().PutStr(string(kv.Key), kv.Value.AsString())
	}
	statusCode := codeToStatusCode(otel.SpanStatusCode(&span))
	s.Status().SetCode(statusCode)

	if hasSubspans {
		createSubSpans(&ss, span, t)
	}
	s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))

	return traces
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(ss *ptrace.ScopeSpans, span request.Span, t request.Timings) {
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
