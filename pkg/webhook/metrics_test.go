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

	m.RecordAttempt("ns", "java")
	m.RecordAttempt("ns", "java")
	m.RecordAttempt("ns", "python")
	m.RecordAttempt("other", "nodejs")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.attempts.WithLabelValues("ns", "java")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.attempts.WithLabelValues("ns", "python")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.attempts.WithLabelValues("other", "nodejs")))

	m.RecordSuccess("ns", "java")
	m.RecordSuccess("ns", "python")
	assert.Equal(t, 1.0, testutil.ToFloat64(m.successes.WithLabelValues("ns", "java")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.successes.WithLabelValues("ns", "python")))

	m.RecordFailure("ns", "java", ErrorTypeMissingSDKVersion)
	m.RecordFailure("ns", "java", ErrorTypeMissingSDKVersion)
	m.RecordFailure("ns", "python", ErrorTypeAlreadyInstrumented)
	m.RecordFailure("other", "nodejs", ErrorTypeLDPreloadConflict)
	assert.Equal(t, 2.0, testutil.ToFloat64(m.failures.WithLabelValues("ns", "java", ErrorTypeMissingSDKVersion)))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.failures.WithLabelValues("ns", "python", ErrorTypeAlreadyInstrumented)))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.failures.WithLabelValues("other", "nodejs", ErrorTypeLDPreloadConflict)))

	m.RecordRestart("ns")
	m.RecordRestart("ns")
	m.RecordRestart("other")
	assert.Equal(t, 2.0, testutil.ToFloat64(m.restarts.WithLabelValues("ns")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.restarts.WithLabelValues("other")))
}

func TestSDKInjectionErrorTypeConstants(t *testing.T) {
	assert.Equal(t, "missing_sdk_version", ErrorTypeMissingSDKVersion)
	assert.Equal(t, "already_instrumented", ErrorTypeAlreadyInstrumented)
	assert.Equal(t, "ld_preload_conflict", ErrorTypeLDPreloadConflict)
	assert.Equal(t, "no_matching_selector", ErrorTypeNoMatchingSelector)
	assert.Equal(t, "patch_generation_failed", ErrorTypePatchGenerationFailed)
	assert.Equal(t, "no_changes_detected", ErrorTypeNoChangesDetected)
	assert.Equal(t, "admission_rejected", ErrorTypeAdmissionRejected)
}
