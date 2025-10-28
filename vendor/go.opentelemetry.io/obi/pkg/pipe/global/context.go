// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph.
type ContextInfo struct {
	// HostID of the host running OBI. Unless testing environments, this value must be
	// automatically set after invoking FetchHostID
	HostID string
	// AppO11y stores context information that is only required for application observability.
	// Its values must be initialized by the App O11y code and shouldn't be accessed from the
	// NetO11y part.
	AppO11y AppO11y
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus *connector.PrometheusManager
	// MetricAttributeGroups will selectively enable or disable diverse groups of attributes
	// in the metric exporters
	MetricAttributeGroups attributes.AttrGroups
	// K8sInformer enables direct access to the Kubernetes API
	K8sInformer *kube.MetadataProvider

	// OverrideAppExportQueue allows overriding the output queue of the application exporter
	// to connect your own application exporters outside the OBI code base. If left unset, OBI will
	// create its own private queue.
	// This is useful when OBI runs in vendored mode
	OverrideAppExportQueue *msg.Queue[[]request.Span]

	// OverrideNetExportQueue allows overriding the output queue of the network exporter
	// to connect your own network exporters outside the OBI code base. If left unset, OBI will
	// create its own private queue.
	// This is useful when OBI runs in vendored mode
	OverrideNetExportQueue *msg.Queue[[]*ebpf.Record]

	// ExtraResourceAttributes allows extending (or overriding) the reported resource attributes in the traces exporters
	ExtraResourceAttributes []attribute.KeyValue

	// OTELMetricsExporter allows sharing the same OTEL exporter through diverse metrics export nodes (Application, Network...)
	OTELMetricsExporter *otelcfg.MetricsExporterInstancer
}

// AppO11y stores context information that is only required for application observability.
type AppO11y struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
}
