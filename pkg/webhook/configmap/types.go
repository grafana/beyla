// Package configmap defines the on-disk shape of the per-node state ConfigMap
// that Beyla writes and the external k8s injection controller consumes. It is
// the public, shared schema between the two repositories.
//
// Only the schema, the keys, and the (un)marshal helpers live here; the
// runtime writer/reader logic lives next to its caller (Beyla's
// StateConfigMapWriter; the injector's ConfigMapReconciler).
package configmap

import (
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const (
	// KeyInstrumentation is the ConfigMap.Data key holding the injection
	// criteria + OTLP destination (an InjectConfig serialized as YAML).
	KeyInstrumentation = "instrumentation.yaml"

	// KeyEligibleForRestart is the ConfigMap.Data key holding the list of
	// workloads whose pre-existing pods should be evicted so the webhook can
	// re-intercept them on recreation (a []EligibleDeployment serialized as
	// YAML).
	KeyEligibleForRestart = "eligible_for_restart.yaml"

	// SelectorAnnotation marks the ConfigMap as one the external injection
	// controller should consume. Its value is unused — presence is what the
	// controller's watch predicate filters on.
	SelectorAnnotation = "beyla.grafana.com/node"
)

// InjectConfig is the YAML document under KeyInstrumentation: a list of
// service-selection globs and the OTLP destination to stamp onto matched
// pods.
type InjectConfig struct {
	// Discovery is a list of service-selection criteria reused verbatim from
	// Beyla's own configuration shape. The injection controller picks the
	// kubernetes metadata fields (k8s_namespace, k8s_pod_name, ...) out of
	// each entry; non-kubernetes fields (open_ports, exe_path, ...) are
	// ignored on the consumer side.
	Discovery services.GlobDefinitionCriteria `yaml:"discovery,omitempty"`

	// OtelExport tells the injection controller what OTLP endpoint and
	// protocol to set on instrumented containers. Empty fields are pruned
	// by Marshal so the document stays minimal.
	OtelExport OtelExport `yaml:"otel_export,omitempty"`
}

// OtelExport is the per-ConfigMap OTLP destination applied to matched pods.
type OtelExport struct {
	Endpoint string `yaml:"endpoint,omitempty"`
	Protocol string `yaml:"protocol,omitempty"`
}

// EligibleDeployment names one workload whose pre-existing pods are
// candidates for eviction. The injection controller cross-checks each entry
// against its in-memory Discovery match before actually evicting.
type EligibleDeployment struct {
	Namespace string `yaml:"namespace"`
	Kind      string `yaml:"kind,omitempty"`
	Name      string `yaml:"name"`
	Language  string `yaml:"language,omitempty"`
}
