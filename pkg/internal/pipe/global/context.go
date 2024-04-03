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
	// K8sEnabled specifies whether kubernetes decoration and discovery is enabled
	K8sEnabled bool
	// AppO11y stores context information that is only required for application observability.
	// Its values must be initialized by the App O11y code and shouldn't be accessed from the
	// NetO11y part.
	// TODO: unify appo11y and neto11y kubernetes informers
	AppO11y AppO11y
	// Metrics  that are internal to the pipe components
	Metrics imetrics.Reporter
	// Prometheus connection manager to coordinate metrics exposition from diverse nodes
	Prometheus *connector.PrometheusManager
}

// AppO11y stores context information that is only required for application observability.
type AppO11y struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
	// K8sInformer enables direct access to the Kubernetes API
	K8sInformer *kube2.Metadata
	// K8sDatabase provides access to shared kubernetes metadata
	K8sDatabase *kube.Database
}
