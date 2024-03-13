package grafanaagent

import (
	"context"
	"log/slog"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// MetricsReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func MetricsReceiver(ctx context.Context, cfg beyla.Config) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreMetrics {
					continue
				}

				for _, tc := range cfg.MetricsReceiver.Metrics {
					m := generateMetrics(&cfg.Metrics, span)
					err := tc.ConsumeMetrics(ctx, m)
					if err != nil {
						slog.Error("error sending metrics to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}

func generateMetrics(cfg *otel.MetricsConfig, span *request.Span) pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	resourceAttrs := AttrsToMap(otel.Resource(span.ServiceID).Attributes())
	resourceAttrs.CopyTo(rm.Resource().Attributes())

	ilm := rm.ScopeMetrics().AppendEmpty()
	ilm.Scope().SetName(otel.ReporterName)
	ilm.Metrics().AppendEmpty()
	t := span.Timings()
	duration := t.End.Sub(t.RequestStart).Seconds()
	attrs := AttrsToMap(otel.MetricAttributes(cfg, span))
	switch span.Type {
	case request.EventTypeHTTP:
		m := generateHistogram(otel.HTTPServerDuration, "s", duration, t.RequestStart, attrs, cfg.Buckets.DurationHistogram)
		m.CopyTo(ilm.Metrics().At(0))

		ilm.Metrics().AppendEmpty()
		m = generateHistogram(otel.HTTPServerRequestSize, "By", float64(span.ContentLength), t.RequestStart, attrs, cfg.Buckets.RequestSizeHistogram)
		m.CopyTo(ilm.Metrics().At(1))
	case request.EventTypeHTTPClient:
		m := generateHistogram(otel.HTTPClientDuration, "s", duration, t.RequestStart, attrs, cfg.Buckets.DurationHistogram)
		m.CopyTo(ilm.Metrics().At(0))

		ilm.Metrics().AppendEmpty()
		m = generateHistogram(otel.HTTPClientRequestSize, "By", float64(span.ContentLength), t.RequestStart, attrs, cfg.Buckets.RequestSizeHistogram)
		m.CopyTo(ilm.Metrics().At(1))
	case request.EventTypeGRPC:
		m := generateHistogram(otel.RPCServerDuration, "s", duration, t.RequestStart, attrs, cfg.Buckets.DurationHistogram)
		m.CopyTo(ilm.Metrics().At(0))
	case request.EventTypeGRPCClient:
		m := generateHistogram(otel.RPCClientDuration, "s", duration, t.RequestStart, attrs, cfg.Buckets.DurationHistogram)
		m.CopyTo(ilm.Metrics().At(0))
	case request.EventTypeSQLClient:
		m := generateHistogram(otel.SQLClientDuration, "s", duration, t.RequestStart, attrs, cfg.Buckets.DurationHistogram)
		m.CopyTo(ilm.Metrics().At(0))
	}

	return metrics
}

func generateHistogram(metricName string, unit string, value float64, ts time.Time, attrs pcommon.Map, buckets []float64) pmetric.Metric {
	// Prepare the metric
	m := pmetric.NewMetric()
	m.SetName(metricName)
	m.SetUnit(unit)
	m.SetEmptyHistogram().SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)

	// Prepare the data point
	timestamp := pcommon.NewTimestampFromTime(time.Now())
	startTS := pcommon.NewTimestampFromTime(ts)
	dp := m.Histogram().DataPoints().AppendEmpty()
	dp.SetTimestamp(timestamp)
	dp.SetStartTimestamp(startTS)
	dp.ExplicitBounds().FromRaw(buckets)

	// Set the value
	dp.SetCount(1)
	dp.SetSum(value)

	// Set metric attributes
	attrs.CopyTo(dp.Attributes())
	return m
}
