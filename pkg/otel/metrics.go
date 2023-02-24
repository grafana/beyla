package otel

import (
	"context"

	"github.com/grafana/http-autoinstrument/pkg/spanner"
	"go.opentelemetry.io/otel/attribute"
)

func (r *Reporter) ReportMetrics(spans <-chan spanner.HttpRequestSpan) {
	for span := range spans {
		// TODO: for more accuracy, there must be a way to set the metric time from the actual span end time
		r.duration.Record(context.TODO(),
			span.End.Sub(span.Start).Seconds()*1000,
			attribute.String("http.method", span.Method),
			attribute.Int("http.status_code", span.Status),
			attribute.String("http.target", span.Path),
		)
	}
}
