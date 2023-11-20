package global

import (
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/kube"
)

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph.
type ContextInfo struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
	// K8sDecoration specifies whether kubernetes decoration is enabled
	K8sDecoration bool
	// TODO: describe
	K8sDatabase *kube.Database
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus *connector.PrometheusManager
}
