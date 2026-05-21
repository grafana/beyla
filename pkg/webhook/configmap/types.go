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

// WebhookInstrument is a subset of services.GlobDefinitionCriteria because
// GlobDefinitionCriteria is only designed for unmarshaling and the
// marshal+unmarshal operation is not idempotent (and makes the injector controller
// to fail).
// GlobDefinitionCriteria contains many attributes that are not
// part of the webhook discovery so we copy here only the ones that are
// actually needed.
type WebhookInstrument []WebhookKubeOnlySelector

type WebhookKubeOnlySelector struct {
	// PodLabels allows matching against the labels of a pod
	PodLabels map[string]*services.GlobAttr `yaml:"k8s_pod_labels,omitempty"`

	// PodAnnotations allows matching against the annotations of a pod
	PodAnnotations map[string]*services.GlobAttr `yaml:"k8s_pod_annotations,omitempty"`

	// Metadata stores other Kubernetes object metadata
	Metadata services.MetadataGlobMap `yaml:",inline" mapstructure:",remain"`
}

// InjectConfig is the YAML document under KeyInstrumentation: a list of
// service-selection globs and the OTLP destination to stamp onto matched
// pods.
type InjectConfig struct {
	// Discovery is a list of service-selection criteria reused verbatim from
	// Beyla's own configuration shape. The injection controller picks the
	// kubernetes metadata fields (k8s_namespace, k8s_pod_name, ...) out of
	// each entry; non-kubernetes fields (open_ports, exe_path, ...) are
	// ignored on the consumer side.
	Discovery WebhookInstrument `yaml:"discovery,omitempty"`

	// OtelExport tells the injection controller what OTLP endpoint and
	// protocol to set on instrumented containers. Empty fields are pruned
	// by Marshal so the document stays minimal.
	OtelExport OtelExport `yaml:"otel_export,omitempty"`

	// ExportedSignals configuration for SDK instrumentation
	// Controls which signals (traces, metrics, logs) should be exported from injected SDKs
	ExportedSignals SDKExportedSignals `yaml:"otel_exported_signals,omitempty"`

	// OCI image mount, supported on k8s 1.31+. Must not be empty.
	ImageVolumePath string `yaml:"image_volume_path,omitempty"`

	// Default sampler configuration for SDK instrumentation
	// This is used when no sampler is specified in the selector
	DefaultSampler *services.SamplerConfig `yaml:"trace_sampler,omitempty"`

	// Propagators configuration for SDK instrumentation
	// Common values: tracecontext, baggage, b3, b3multi, jaeger, xray
	Propagators []string `yaml:"trace_propagators,omitempty"`

	// Resource attributes related settings
	Resources SDKResource `yaml:"resources,omitempty"`
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

// SDKExportedSignals defines which telemetry signals should be exported from injected SDKs.
// These settings are independent from the global export configuration and allow
// the injector to export metrics/traces/logs even when Beyla uses Prometheus for metrics.
type SDKExportedSignals struct {
	// Traces enables trace export from injected SDKs via OTLP
	// Defaults to true (enabled) when not explicitly set
	Traces *bool `yaml:"traces,omitempty" env:"BEYLA_SDK_EXPORT_TRACES"`
	// Metrics enables metric export from injected SDKs via OTLP
	// Defaults to true (enabled) when not explicitly set
	// Note: SDKs can only export via OTLP, not Prometheus scraping
	Metrics *bool `yaml:"metrics,omitempty" env:"BEYLA_SDK_EXPORT_METRICS"`
	// Logs enables log export from injected SDKs via OTLP
	// Defaults to false (disabled) when not explicitly set
	Logs *bool `yaml:"logs,omitempty" env:"BEYLA_SDK_EXPORT_LOGS"`
}

// TracesEnabled returns whether trace export is enabled for SDK instrumentation
// Defaults to true when not explicitly set
func (e SDKExportedSignals) TracesEnabled() bool {
	if e.Traces == nil {
		return true // default to enabled
	}
	return *e.Traces
}

// MetricsEnabled returns whether metric export is enabled for SDK instrumentation
// Defaults to true when not explicitly set
func (e SDKExportedSignals) MetricsEnabled() bool {
	if e.Metrics == nil {
		return true // default to enabled
	}
	return *e.Metrics
}

// LogsEnabled returns whether log export is enabled for SDK instrumentation
// Defaults to false when not explicitly set
func (e SDKExportedSignals) LogsEnabled() bool {
	if e.Logs == nil {
		return false // default to disabled
	}
	return *e.Logs
}

// Resource defines the configuration for the resource attributes, as defined by the OpenTelemetry specification.
// See also: https://github.com/open-telemetry/opentelemetry-specification/blob/v1.8.0/specification/overview.md#resources
type SDKResource struct {
	// Attributes defines attributes that are added to the resource.
	// For example environment: dev
	// +optional
	Attributes map[string]string `yaml:"attributes,omitempty" env:"BEYLA_RESOURCE_ATTRIBUTES"`

	// AddK8sUIDAttributes defines whether K8s UID attributes should be collected (e.g. k8s.deployment.uid).
	// +optional
	AddK8sUIDAttributes bool `yaml:"add_k8s_uid_attributes,omitempty" env:"BEYLA_RESOURCE_ADD_K8S_UID_ATTRIBUTES"`

	// AddK8sIPAttribute defines whether the k8s.pod.ip resource attribute should be set
	// from the Kubernetes downward API (status.podIP). Useful for environments where the
	// OTel k8sattributesprocessor cannot infer the pod IP from the connection source
	// (e.g. clusters behind a NAT gateway).
	// +optional
	AddK8sIPAttribute bool `yaml:"add_k8s_ip_attribute,omitempty" env:"BEYLA_RESOURCE_ADD_K8S_IP_ATTRIBUTE"`

	// UseLabelsForResourceAttributes defines whether to use common labels for resource attributes:
	// Note: first entry wins:
	//   - `app.kubernetes.io/instance` becomes `service.name`
	//   - `app.kubernetes.io/name` becomes `service.name`
	//   - `app.kubernetes.io/version` becomes `service.version`
	UseLabelsForResourceAttributes bool `yaml:"use_k8s_labels_for_resource_attributes,omitempty" env:"BEYLA_RESOURCE_USE_LABELS_FOR_RESOURCE_ATTRIBUTES"`
}
