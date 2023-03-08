package otel

import (
	"context"

	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"go.opentelemetry.io/otel/attribute"

	trace2 "go.opentelemetry.io/otel/trace"
)

func (r *Reporter) ReportTraces(spans <-chan spanner.HTTPRequestSpan) {
	tracer := r.traceProvider.Tracer(reporterName)
	for span := range spans {
		// TODO: there must be a better way to instantiate spans
		_, sp := tracer.Start(context.TODO(), "session",
			trace2.WithTimestamp(span.Start),
			trace2.WithAttributes(
				// TODO: use standard names
				attribute.Int("http.status", span.Status),
				attribute.String("http.path", span.Path),
				attribute.String("http.method", span.Method),
				// TODO: add src/dst ip and dst port
			),
			// TODO: trace2.WithSpanKind()
		)
		sp.End(trace2.WithTimestamp(span.End))
	}
}
