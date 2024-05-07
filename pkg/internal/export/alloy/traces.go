package alloy

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(ctx context.Context, otelCfg *otel.TracesConfig, cfg *beyla.TracesReceiverConfig) pipe.FinalProvider[[]request.Span] {
	return (&tracesReceiver{ctx: ctx, cfg: cfg, otelCfg: otelCfg}).provideLoop
}

type tracesReceiver struct {
	ctx     context.Context
	cfg     *beyla.TracesReceiverConfig
	otelCfg *otel.TracesConfig
}

func (tr *tracesReceiver) provideLoop() (pipe.FinalFunc[[]request.Span], error) {
	if !tr.cfg.Enabled() {
		return pipe.IgnoreFinal[[]request.Span](), nil
	}
	return func(in <-chan []request.Span) {
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}

				for _, tc := range tr.cfg.Traces {
					traces := generateTraces(span, tr.otelCfg)
					err := tc.ConsumeTraces(tr.ctx, traces)
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}

// generateTraces creates a ptrace.Traces from a request.Span
func generateTraces(span *request.Span, cfg *otel.TracesConfig) ptrace.Traces {
	t := span.Timings()
	start := otel.SpanStartTime(t)
	hasSubSpans := t.Start.After(start)
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	resourceAttrs := attrsToMap(otel.Resource(span.ServiceID).Attributes())
	resourceAttrs.CopyTo(rs.Resource().Attributes())

	traceID := pcommon.TraceID(span.TraceID)
	spanID := pcommon.SpanID(otel.RandomSpanID())
	if traceID.IsEmpty() {
		traceID = pcommon.TraceID(otel.RandomTraceID())
	}

	if hasSubSpans {
		createSubSpans(span, spanID, traceID, &ss, t)
	} else if span.SpanID.IsValid() {
		spanID = pcommon.SpanID(span.SpanID)
	}

	// Create a parent span for the whole request session
	s := ss.Spans().AppendEmpty()
	s.SetName(otel.TraceName(span))
	s.SetKind(ptrace.SpanKind(otel.SpanKind(span)))
	s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

	// Set trace and span IDs
	s.SetSpanID(spanID)
	s.SetTraceID(traceID)
	if span.ParentSpanID.IsValid() {
		s.SetParentSpanID(pcommon.SpanID(span.ParentSpanID))
	}

	// Set span attributes
	attrs := otel.TraceAttributes(span, cfg)
	m := attrsToMap(attrs)
	m.CopyTo(s.Attributes())

	// Set status code
	statusCode := codeToStatusCode(otel.SpanStatusCode(span))
	s.Status().SetCode(statusCode)
	s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	return traces
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(span *request.Span, parentSpanID pcommon.SpanID, traceID pcommon.TraceID, ss *ptrace.ScopeSpans, t request.Timings) {
	// Create a child span showing the queue time
	spQ := ss.Spans().AppendEmpty()
	spQ.SetName("in queue")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(t.RequestStart))
	spQ.SetKind(ptrace.SpanKindInternal)
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spQ.SetTraceID(traceID)
	spQ.SetSpanID(pcommon.SpanID(otel.RandomSpanID()))
	spQ.SetParentSpanID(parentSpanID)

	// Create a child span showing the processing time
	spP := ss.Spans().AppendEmpty()
	spP.SetName("processing")
	spP.SetStartTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spP.SetKind(ptrace.SpanKindInternal)
	spP.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	spP.SetTraceID(traceID)
	if span.SpanID.IsValid() {
		spP.SetSpanID(pcommon.SpanID(span.SpanID))
	} else {
		spP.SetSpanID(pcommon.SpanID(otel.RandomSpanID()))
	}
	spP.SetParentSpanID(parentSpanID)
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
