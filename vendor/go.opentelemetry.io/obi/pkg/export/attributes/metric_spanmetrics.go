// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"strings"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// Span metrics, aggregated from spans rather than measured directly. Both exporters emit them, so
// they are declared once here and the Prometheus name is derived from the OTLP definition.
//
// The underscore-shaped OTEL names are the Grafana convention, matched literally by Tempo. For the
// same reason those histograms declare no unit: a unit would add a _seconds suffix their consumers
// do not expect.
var (
	// application_span (deprecated).
	SpanMetricsLatencyLegacy = metric(Name{
		Section: "traces.spanmetrics.latency",
		OTEL:    "traces_spanmetrics_latency",
		Type:    InstrumentHistogram,
	})
	SpanMetricsCallsLegacy = metric(Name{
		Section: "traces.spanmetrics.calls",
		OTEL:    "traces_spanmetrics_calls_total",
		Type:    InstrumentCounter,
	})

	// application_span_otel, matching the spanmetrics connector's traces.span.metrics namespace.
	SpanMetricsDurationOTel = metric(Name{
		Section: "traces.span.metrics.duration",
		OTEL:    "traces.span.metrics.duration",
		Unit:    "s",
		Type:    InstrumentHistogram,
	})
	SpanMetricsCallsOTel = metric(Name{
		Section: "traces.span.metrics.calls",
		OTEL:    "traces.span.metrics.calls",
		Type:    InstrumentCounter,
	})

	// application_span_sizes (deprecated). Same Grafana-convention family as the legacy span
	// metrics, with no OTel-named equivalent, so one name serves both formats.
	SpanMetricsRequestSize = metric(Name{
		Section: "traces.spanmetrics.size",
		OTEL:    "traces_spanmetrics_size_total",
		Type:    InstrumentCounter,
	})
	SpanMetricsResponseSize = metric(Name{
		Section: "traces.spanmetrics.response.size",
		OTEL:    "traces_spanmetrics_response_size_total",
		Type:    InstrumentCounter,
	})
)

var SpanMetrics = []Name{
	SpanMetricsLatencyLegacy,
	SpanMetricsCallsLegacy,
	SpanMetricsDurationOTel,
	SpanMetricsCallsOTel,
	SpanMetricsRequestSize,
	SpanMetricsResponseSize,
}

// SpanMetadataValue returns the workload metadata key and value for a selected span
// metric key. With aliases, a key written with underscores that is missing from the
// metadata also matches its dotted form.
func SpanMetadataValue(metadata map[attr.Name]string, name attr.Name, aliases bool) (attr.Name, string, bool) {
	if value, ok := metadata[name]; ok {
		return name, value, true
	}
	if !aliases {
		return name, "", false
	}
	dotted := attr.Name(strings.ReplaceAll(string(name), "_", "."))
	if dotted == name {
		return name, "", false
	}
	value, ok := metadata[dotted]
	return dotted, value, ok
}
