package webhook

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestSDKInjectionMetrics(t *testing.T) {
	m := NewSDKInjectionMetrics()
	prometheus.NewRegistry().MustRegister(m.Collectors()...)

	m.RecordRequest("ns", "Deployment", "my-app", "java", OutcomeSuccess)
	m.RecordRequest("ns", "Deployment", "my-app", "java", OutcomeSuccess)
	m.RecordRequest("ns", "Deployment", "my-app", "python", ErrorTypeMissingSDKVersion)
	m.RecordRequest("other", "ReplicaSet", "other-app", "nodejs", ErrorTypeLDPreloadConflict)
	assert.Equal(t, 2.0, testutil.ToFloat64(m.requests.WithLabelValues("ns", "Deployment", "my-app", "java", OutcomeSuccess)))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.requests.WithLabelValues("ns", "Deployment", "my-app", "python", ErrorTypeMissingSDKVersion)))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.requests.WithLabelValues("other", "ReplicaSet", "other-app", "nodejs", ErrorTypeLDPreloadConflict)))

	// early-exit paths have no workload context
	m.RecordRequest("ns", "", "", "java", ErrorTypeAdmissionRejected)
	assert.Equal(t, 1.0, testutil.ToFloat64(m.requests.WithLabelValues("ns", "", "", "java", ErrorTypeAdmissionRejected)))

	m.RecordRestart("ns", "Deployment", "my-app", "java")
	m.RecordRestart("ns", "Deployment", "my-app", "java")
	m.RecordRestart("other", "DaemonSet", "other-app", "python")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.restarts.WithLabelValues("ns", "Deployment", "my-app", "java")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.restarts.WithLabelValues("other", "DaemonSet", "other-app", "python")))
}

func TestSDKInjectionOutcomeConstants(t *testing.T) {
	assert.Equal(t, "success", OutcomeSuccess)
	assert.Equal(t, "missing_sdk_version", ErrorTypeMissingSDKVersion)
	assert.Equal(t, "already_instrumented", ErrorTypeAlreadyInstrumented)
	assert.Equal(t, "ld_preload_conflict", ErrorTypeLDPreloadConflict)
	assert.Equal(t, "no_matching_selector", ErrorTypeNoMatchingSelector)
	assert.Equal(t, "patch_generation_failed", ErrorTypePatchGenerationFailed)
	assert.Equal(t, "no_changes_detected", ErrorTypeNoChangesDetected)
	assert.Equal(t, "admission_rejected", ErrorTypeAdmissionRejected)
}
