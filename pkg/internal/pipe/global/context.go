package global

import (
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/imetrics"
)

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph.
type ContextInfo struct {
	// ChannelBufferLen specifies, for each channel that is created in the pipeline, its buffer length
	ChannelBufferLen int
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
	// ServiceName is the value of the service_name config attribute, or the discovered value
	ServiceName string
	// ServiceNamespace is the value of the service_namespace config attribute
	ServiceNamespace string
	// K8sDecoration specifies whether kubernetes decoration is enabled
	K8sDecoration bool
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus *connector.PrometheusManager
}
