// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

// Span metrics, aggregated from spans rather than measured directly. Both exporters emit them, so
// they are declared once here and the Prometheus name is derived from the OTLP definition.
//
// They carry no Section: user-provided attribute selection is disabled for them.
//
// The underscore-shaped OTEL names are the Grafana convention, matched literally by Tempo. For the
// same reason those histograms declare no unit: a unit would add a _seconds suffix their consumers
// do not expect.
var (
	// application_span (deprecated).
	SpanMetricsLatencyLegacy = metric(Name{
		OTEL: "traces_spanmetrics_latency",
		Type: InstrumentHistogram,
	})
	SpanMetricsCallsLegacy = metric(Name{
		OTEL: "traces_spanmetrics_calls_total",
		Type: InstrumentCounter,
	})

	// application_span_otel, matching the spanmetrics connector's traces.span.metrics namespace.
	SpanMetricsDurationOTel = metric(Name{
		OTEL: "traces.span.metrics.duration",
		Unit: "s",
		Type: InstrumentHistogram,
	})
	SpanMetricsCallsOTel = metric(Name{
		OTEL: "traces.span.metrics.calls",
		Type: InstrumentCounter,
	})

	// application_span_sizes (deprecated). Same Grafana-convention family as the legacy span
	// metrics, with no OTel-named equivalent, so one name serves both formats.
	SpanMetricsRequestSize = metric(Name{
		OTEL: "traces_spanmetrics_size_total",
		Type: InstrumentCounter,
	})
	SpanMetricsResponseSize = metric(Name{
		OTEL: "traces_spanmetrics_response_size_total",
		Type: InstrumentCounter,
	})
)
