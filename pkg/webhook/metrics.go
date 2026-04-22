package webhook

import (
	"github.com/prometheus/client_golang/prometheus"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// SDKInjectionMetrics tracks metrics for SDK injection operations
type SDKInjectionMetrics struct {
	requests *prometheus.CounterVec
	restarts *prometheus.CounterVec
}

// NewSDKInjectionMetrics creates and registers SDK injection metrics
func NewSDKInjectionMetrics() *SDKInjectionMetrics {
	return &SDKInjectionMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_requests_total",
			Help: "SDK injection admission requests by outcome",
		}, []string{"k8s_namespace_name", "k8s_workload_kind", "k8s_workload_name", "language", "outcome"}),
		restarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_restarts_total",
			Help: "Deployment restarts triggered for SDK injection",
		}, []string{"k8s_namespace_name", "k8s_workload_name"}),
	}
}

// Collectors returns all prometheus collectors for registration
func (m *SDKInjectionMetrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{m.requests, m.restarts}
}

// RecordRequest records one admission request with its outcome.
// workloadKind and workloadName are empty for failures that occur before the pod is parsed.
func (m *SDKInjectionMetrics) RecordRequest(namespace, workloadKind, workloadName, language, outcome string) {
	m.requests.WithLabelValues(namespace, workloadKind, workloadName, language, outcome).Inc()
}

// RecordRestart records a deployment restart triggered for SDK injection.
func (m *SDKInjectionMetrics) RecordRestart(namespace, workloadName string) {
	m.restarts.WithLabelValues(namespace, workloadName).Inc()
}

// Outcome constants for SDK injection requests.
const (
	OutcomeSuccess = "success"
)

// Failure outcome constants for SDK injection requests.
const (
	ErrorTypeMissingSDKVersion     = "missing_sdk_version"
	ErrorTypeAlreadyInstrumented   = "already_instrumented"
	ErrorTypeLDPreloadConflict     = "ld_preload_conflict"
	ErrorTypeNoMatchingSelector    = "no_matching_selector"
	ErrorTypePatchGenerationFailed = "patch_generation_failed"
	ErrorTypeNoChangesDetected     = "no_changes_detected"
	ErrorTypeAdmissionRejected     = "admission_rejected"
)
