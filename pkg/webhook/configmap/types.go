// Package configmap defines the on-disk shape of the per-node state ConfigMap
// that Beyla writes and the external k8s injection controller consumes. It is
// the public, shared schema between the two repositories.
//
// The package contains the schema types, the ConfigMap key constants, and the
// Selector.Match logic (in match.go). Runtime writer/reader logic lives next
// to its caller (Beyla's StateConfigMapWriter; the injector's ConfigMapReconciler).
package configmap

import (
	corev1 "k8s.io/api/core/v1"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

const (
	// KeyInstrumentation is the ConfigMap.Data key holding the injection
	// criteria + per-rule config (an InjectConfig serialized as YAML).
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

// WebhookInstrument is the list of selectors from the Beyla injector config
// that determine which pods to instrument. It carries selectors only — no
// per-rule config. When Beyla writes the state ConfigMap it promotes each
// Selector into a full Rule by pairing it with the OTLP destination env vars
// derived from Beyla's own export configuration (see buildInjectConfig).
type WebhookInstrument []Selector

// InjectConfig is the YAML document under KeyInstrumentation. Rules are
// evaluated in order; the first rule whose selector matches a pod wins.
// No match means no instrumentation.
type InjectConfig struct {
	Rules []Rule `yaml:"rules,omitempty"`
}

// Rule pairs a selector with the instrumentation config to apply when the
// selector matches.
type Rule struct {
	Selector Selector   `yaml:"selector,omitempty"`
	Config   RuleConfig `yaml:"config,omitempty"`
}

// Selector determines which pods a Rule applies to. All populated fields must
// match (AND). An empty field is a wildcard.
type Selector struct {
	// Namespaces lists namespace name globs. Empty means all namespaces.
	// A pod matches if its namespace matches any entry (OR semantics).
	Namespaces []services.GlobAttr `yaml:"namespaces,omitempty"`
	// OwnerName is a glob matched against the pod's resolved owning resource
	// name. For a pod owned by a ReplicaSet that is itself owned by a
	// Deployment, both the ReplicaSet name and the Deployment name are tried.
	// Empty means any owner name.
	OwnerName services.GlobAttr `yaml:"ownerName,omitempty"`
	// OwnerKind restricts matching to a specific owner kind: Deployment,
	// ReplicaSet, StatefulSet, or DaemonSet. Empty means any kind.
	OwnerKind string `yaml:"ownerKind,omitempty"`
	// PodLabels maps label keys to value globs. Empty means all pods.
	// All entries must match (AND semantics).
	PodLabels map[string]services.GlobAttr `yaml:"podLabels,omitempty"`
	// PodAnnotations maps annotation keys to value globs. Empty means all pods.
	// All entries must match (AND semantics).
	PodAnnotations map[string]services.GlobAttr `yaml:"podAnnotations,omitempty"`
}

// RuleConfig is the instrumentation configuration stamped onto matched pods.
type RuleConfig struct {
	// Env is the list of environment variables to set on instrumented containers.
	// Supports all corev1.EnvVar sources (valueFrom.secretKeyRef, etc.).
	Env []corev1.EnvVar `yaml:"env,omitempty"`
	// TODO: add declarativeConfig support — when set, mount the inline OTel
	// declarative config (file_format: "1.0") as a ConfigMap and set
	// OTEL_CONFIG_FILE on matched containers. Requires volume mount + env var
	// injection in the mutator before this field can be added to the schema.
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
