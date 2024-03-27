package global

import (
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	kube2 "github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/transform/kube"
)

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph.
type ContextInfo struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
	// K8sEnabled specifies whether kubernetes decoration and discovery is enabled
	K8sEnabled bool
	// K8sInformer enables direct access to the Kubernetes API
	K8sInformer *kube2.Metadata
	// K8sDatabase provides access to shared kubernetes metadata
	K8sDatabase *kube.Database
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus *connector.PrometheusManager
}
