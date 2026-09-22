// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

// Service graph metrics. Both exporters emit them, so they are declared once here and the
// Prometheus name is derived from the OTLP definition.
//
// They carry no Section: user-provided attribute selection is disabled for them.
//
// The names match the collector-contrib servicegraph connector exactly, which itself emits
// underscore-shaped names, so they must not be renamed.
var (
	ServiceGraphClient = metric(Name{
		OTEL: "traces_service_graph_request_client",
		Unit: "s",
		Type: InstrumentHistogram,
	})
	ServiceGraphServer = metric(Name{
		OTEL: "traces_service_graph_request_server",
		Unit: "s",
		Type: InstrumentHistogram,
	})
	ServiceGraphFailed = metric(Name{
		OTEL: "traces_service_graph_request_failed_total",
		Type: InstrumentCounter,
	})
	ServiceGraphTotal = metric(Name{
		OTEL: "traces_service_graph_request_total",
		Type: InstrumentCounter,
	})
)
