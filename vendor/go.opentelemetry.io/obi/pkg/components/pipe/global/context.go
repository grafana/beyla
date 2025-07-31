// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package global

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/connector"
	"go.opentelemetry.io/obi/pkg/components/imetrics"
	kube2 "go.opentelemetry.io/obi/pkg/components/kube"
	"go.opentelemetry.io/obi/pkg/export/attributes"
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
	K8sInformer *kube2.MetadataProvider

	// OverrideAppExportQueue
	OverrideAppExportQueue *msg.Queue[[]request.Span]

	// ExtraResourceAttributes allows extending (or overriding) the reported resource attributes in the traces exporters
	ExtraResourceAttributes []attribute.KeyValue
}

// AppO11y stores context information that is only required for application observability.
type AppO11y struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
}
