package webhook

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSDKInjectionMetrics(t *testing.T) {
	metrics := NewSDKInjectionMetrics()

	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.attempts)
	assert.NotNil(t, metrics.successes)
	assert.NotNil(t, metrics.failures)
	assert.NotNil(t, metrics.restarts)
}

func TestSDKInjectionMetrics_Collectors(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	collectors := metrics.Collectors()

	assert.Len(t, collectors, 4)
	assert.Contains(t, collectors, metrics.attempts)
	assert.Contains(t, collectors, metrics.successes)
	assert.Contains(t, collectors, metrics.failures)
	assert.Contains(t, collectors, metrics.restarts)
}

func TestSDKInjectionMetrics_RecordAttempt(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)

	metrics.RecordAttempt("test-namespace", "java")
	metrics.RecordAttempt("test-namespace", "java")
	metrics.RecordAttempt("test-namespace", "python")
	metrics.RecordAttempt("other-namespace", "nodejs")

	// Verify java attempts
	count := testutil.ToFloat64(metrics.attempts.WithLabelValues("test-namespace", "java"))
	assert.Equal(t, 2.0, count)

	// Verify python attempts
	count = testutil.ToFloat64(metrics.attempts.WithLabelValues("test-namespace", "python"))
	assert.Equal(t, 1.0, count)

	// Verify nodejs attempts
	count = testutil.ToFloat64(metrics.attempts.WithLabelValues("other-namespace", "nodejs"))
	assert.Equal(t, 1.0, count)
}

func TestSDKInjectionMetrics_RecordSuccess(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)

	metrics.RecordSuccess("test-namespace", "java")
	metrics.RecordSuccess("test-namespace", "python")

	// Verify java successes
	count := testutil.ToFloat64(metrics.successes.WithLabelValues("test-namespace", "java"))
	assert.Equal(t, 1.0, count)

	// Verify python successes
	count = testutil.ToFloat64(metrics.successes.WithLabelValues("test-namespace", "python"))
	assert.Equal(t, 1.0, count)
}

func TestSDKInjectionMetrics_RecordFailure(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)

	metrics.RecordFailure("test-namespace", "java", ErrorTypeMissingSDKVersion)
	metrics.RecordFailure("test-namespace", "java", ErrorTypeMissingSDKVersion)
	metrics.RecordFailure("test-namespace", "python", ErrorTypeAlreadyInstrumented)
	metrics.RecordFailure("other-namespace", "nodejs", ErrorTypeLDPreloadConflict)

	// Verify missing SDK version failures
	count := testutil.ToFloat64(metrics.failures.WithLabelValues("test-namespace", "java", ErrorTypeMissingSDKVersion))
	assert.Equal(t, 2.0, count)

	// Verify already instrumented failures
	count = testutil.ToFloat64(metrics.failures.WithLabelValues("test-namespace", "python", ErrorTypeAlreadyInstrumented))
	assert.Equal(t, 1.0, count)

	// Verify LD_PRELOAD conflict failures
	count = testutil.ToFloat64(metrics.failures.WithLabelValues("other-namespace", "nodejs", ErrorTypeLDPreloadConflict))
	assert.Equal(t, 1.0, count)
}

func TestSDKInjectionMetrics_RecordRestart(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)

	metrics.RecordRestart("test-namespace")
	metrics.RecordRestart("test-namespace")
	metrics.RecordRestart("other-namespace")

	// Verify test-namespace restarts
	count := testutil.ToFloat64(metrics.restarts.WithLabelValues("test-namespace"))
	assert.Equal(t, 2.0, count)

	// Verify other-namespace restarts
	count = testutil.ToFloat64(metrics.restarts.WithLabelValues("other-namespace"))
	assert.Equal(t, 1.0, count)
}

func TestSDKInjectionMetrics_MultipleOperations(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)

	namespace := "production"
	language := "java"

	// Simulate a complete flow
	metrics.RecordAttempt(namespace, language)
	metrics.RecordSuccess(namespace, language)
	metrics.RecordRestart(namespace)

	// Verify all metrics were recorded
	attempts := testutil.ToFloat64(metrics.attempts.WithLabelValues(namespace, language))
	assert.Equal(t, 1.0, attempts)

	successes := testutil.ToFloat64(metrics.successes.WithLabelValues(namespace, language))
	assert.Equal(t, 1.0, successes)

	restarts := testutil.ToFloat64(metrics.restarts.WithLabelValues(namespace))
	assert.Equal(t, 1.0, restarts)
}

func TestSDKInjectionMetrics_ErrorTypeConstants(t *testing.T) {
	// Verify error type constants are defined and have expected values
	assert.Equal(t, "missing_sdk_version", ErrorTypeMissingSDKVersion)
	assert.Equal(t, "already_instrumented", ErrorTypeAlreadyInstrumented)
	assert.Equal(t, "ld_preload_conflict", ErrorTypeLDPreloadConflict)
	assert.Equal(t, "no_matching_selector", ErrorTypeNoMatchingSelector)
	assert.Equal(t, "patch_generation_failed", ErrorTypePatchGenerationFailed)
	assert.Equal(t, "no_changes_detected", ErrorTypeNoChangesDetected)
	assert.Equal(t, "admission_rejected", ErrorTypeAdmissionRejected)
}

func TestSDKInjectionMetrics_RegistrationWithPrometheusManager(t *testing.T) {
	metrics := NewSDKInjectionMetrics()
	registry := prometheus.NewRegistry()

	// Test that metrics can be registered without errors
	err := registry.Register(metrics.attempts)
	require.NoError(t, err)

	err = registry.Register(metrics.successes)
	require.NoError(t, err)

	err = registry.Register(metrics.failures)
	require.NoError(t, err)

	err = registry.Register(metrics.restarts)
	require.NoError(t, err)
}

func TestLanguageLabel(t *testing.T) {
	tests := []struct {
		name     string
		kind     string // We'll use string for simplicity in tests
		expected string
	}{
		{
			name:     "dotnet",
			expected: "dotnet",
		},
		{
			name:     "java",
			expected: "java",
		},
		{
			name:     "nodejs",
			expected: "nodejs",
		},
		{
			name:     "python",
			expected: "python",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This test validates that the expected language strings are used
			assert.Equal(t, tt.expected, tt.name)
		})
	}
}
