package extraattributes

import (
	"testing"

	"github.com/stretchr/testify/assert"

	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
)

// TestMetric_DerivedPromNames pins the Prometheus names derived from the OTLP definition
// of Beyla's own process metrics. They must not change silently: renaming any of them is
// a breaking change for users' dashboards and alerts.
func TestMetric_DerivedPromNames(t *testing.T) {
	for _, tc := range []struct {
		name     attributes.Name
		expected string
	}{
		{ProcessCPUTime, "process_cpu_time_seconds_total"},
		{ProcessCPUUtilization, "process_cpu_utilization_ratio"},
		{ProcessMemoryUsage, "process_memory_usage_bytes"},
		{ProcessMemoryVirtual, "process_memory_virtual_bytes"},
		{ProcessDiskIO, "process_disk_io_bytes_total"},
		{ProcessNetIO, "process_network_io_bytes_total"},
	} {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.name.Prom)
		})
	}
}
