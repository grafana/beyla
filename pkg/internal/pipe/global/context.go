package global

import (
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	kube2 "github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
)

// ContextInfo stores some context information that must be shared across some nodes of the
// processing graph.
type ContextInfo struct {
	// HostID of the host running Beyla. Unless testing environments, this value must be
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
	MetricAttributeGroups attrobi.AttrGroups
	// K8sInformer enables direct access to the Kubernetes API
	K8sInformer *kube2.MetadataProvider
}

// AppO11y stores context information that is only required for application observability.
type AppO11y struct {
	// ReportRoutes sets whether the metrics should set the http.route attribute
	ReportRoutes bool
}
