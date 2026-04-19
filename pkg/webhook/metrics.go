package webhook

import (
	"github.com/prometheus/client_golang/prometheus"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// SDKInjectionMetrics tracks metrics for SDK injection operations
type SDKInjectionMetrics struct {
	attempts  *prometheus.CounterVec
	successes *prometheus.CounterVec
	failures  *prometheus.CounterVec
	restarts  *prometheus.CounterVec
}

// NewSDKInjectionMetrics creates and registers SDK injection metrics
func NewSDKInjectionMetrics() *SDKInjectionMetrics {
	return &SDKInjectionMetrics{
		attempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_attempts_total",
			Help: "Total SDK injection attempts",
		}, []string{"namespace", "language"}),
		successes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_successes_total",
			Help: "Successful SDK injections",
		}, []string{"namespace", "language"}),
		failures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_failures_total",
			Help: "Failed SDK injections with error classification",
		}, []string{"namespace", "language", "error_type"}),
		restarts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_sdk_injection_restarts_total",
			Help: "Deployment restarts triggered for SDK injection",
		}, []string{"namespace"}),
	}
}

// Collectors returns all prometheus collectors for registration
func (m *SDKInjectionMetrics) Collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.attempts,
		m.successes,
		m.failures,
		m.restarts,
	}
}

// RecordAttempt records an SDK injection attempt
func (m *SDKInjectionMetrics) RecordAttempt(namespace, language string) {
	m.attempts.WithLabelValues(namespace, language).Inc()
}

// RecordSuccess records a successful SDK injection
func (m *SDKInjectionMetrics) RecordSuccess(namespace, language string) {
	m.successes.WithLabelValues(namespace, language).Inc()
}

// RecordFailure records a failed SDK injection with error type
func (m *SDKInjectionMetrics) RecordFailure(namespace, language, errorType string) {
	m.failures.WithLabelValues(namespace, language, errorType).Inc()
}

// RecordRestart records a deployment restart triggered for SDK injection
func (m *SDKInjectionMetrics) RecordRestart(namespace string) {
	m.restarts.WithLabelValues(namespace).Inc()
}

// Error type constants for SDK injection failures
const (
	ErrorTypeMissingSDKVersion      = "missing_sdk_version"
	ErrorTypeAlreadyInstrumented    = "already_instrumented"
	ErrorTypeLDPreloadConflict      = "ld_preload_conflict"
	ErrorTypeNoMatchingLanguage     = "no_matching_language"
	ErrorTypePatchGenerationFailed  = "patch_generation_failed"
	ErrorTypeAdmissionRejected      = "admission_rejected"
)
