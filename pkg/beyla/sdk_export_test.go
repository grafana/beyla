package beyla

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSDKExport_TracesEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		export   SDKExport
		expected bool
	}{
		{
			name:     "nil traces defaults to enabled",
			export:   SDKExport{Traces: nil},
			expected: true,
		},
		{
			name:     "explicitly enabled",
			export:   SDKExport{Traces: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   SDKExport{Traces: &falseVal},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.export.TracesEnabled())
		})
	}
}

func TestSDKExport_MetricsEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		export   SDKExport
		expected bool
	}{
		{
			name:     "nil metrics defaults to enabled",
			export:   SDKExport{Metrics: nil},
			expected: true,
		},
		{
			name:     "explicitly enabled",
			export:   SDKExport{Metrics: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   SDKExport{Metrics: &falseVal},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.export.MetricsEnabled())
		})
	}
}

func TestSDKExport_LogsEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		export   SDKExport
		expected bool
	}{
		{
			name:     "nil logs defaults to disabled",
			export:   SDKExport{Logs: nil},
			expected: false,
		},
		{
			name:     "explicitly enabled",
			export:   SDKExport{Logs: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   SDKExport{Logs: &falseVal},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.export.LogsEnabled())
		})
	}
}
