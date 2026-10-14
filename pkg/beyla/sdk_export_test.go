package beyla

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

func TestSDKExport_TracesEnabled(t *testing.T) {
	trueVal := true
	falseVal := false

	tests := []struct {
		name     string
		export   configmap.SDKExportedSignals
		expected bool
	}{
		{
			name:     "nil traces defaults to enabled",
			export:   configmap.SDKExportedSignals{Traces: nil},
			expected: true,
		},
		{
			name:     "explicitly enabled",
			export:   configmap.SDKExportedSignals{Traces: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   configmap.SDKExportedSignals{Traces: &falseVal},
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
		export   configmap.SDKExportedSignals
		expected bool
	}{
		{
			name:     "nil metrics defaults to enabled",
			export:   configmap.SDKExportedSignals{Metrics: nil},
			expected: true,
		},
		{
			name:     "explicitly enabled",
			export:   configmap.SDKExportedSignals{Metrics: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   configmap.SDKExportedSignals{Metrics: &falseVal},
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
		export   configmap.SDKExportedSignals
		expected bool
	}{
		{
			name:     "nil logs defaults to disabled",
			export:   configmap.SDKExportedSignals{Logs: nil},
			expected: false,
		},
		{
			name:     "explicitly enabled",
			export:   configmap.SDKExportedSignals{Logs: &trueVal},
			expected: true,
		},
		{
			name:     "explicitly disabled",
			export:   configmap.SDKExportedSignals{Logs: &falseVal},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.export.LogsEnabled())
		})
	}
}
