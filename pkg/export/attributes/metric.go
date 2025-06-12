package attributes

import (
	"strings"

	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
)

var (
	ProcessCPUTime = attrobi.Name{
		Section: "process.cpu.time",
		Prom:    "process_cpu_time_seconds_total",
		OTEL:    "process.cpu.time",
	}
	ProcessCPUUtilization = attrobi.Name{
		Section: "process.cpu.utilization",
		Prom:    "process_cpu_utilization_ratio",
		OTEL:    "process.cpu.utilization",
	}
	ProcessMemoryUsage = attrobi.Name{
		Section: "process.memory.usage",
		Prom:    "process_memory_usage_bytes",
		OTEL:    "process.memory.usage",
	}
	ProcessMemoryVirtual = attrobi.Name{
		Section: "process.memory.virtual",
		Prom:    "process_memory_virtual_bytes",
		OTEL:    "process.memory.virtual",
	}
	ProcessDiskIO = attrobi.Name{
		Section: "process.disk.io",
		Prom:    "process_disk_io_bytes_total",
		OTEL:    "process.disk.io",
	}
	ProcessNetIO = attrobi.Name{
		Section: "process.network.io",
		Prom:    "process_network_io_bytes_total",
		OTEL:    "process.network.io",
	}
)

// normalizeMetric will facilitate the user-input in the attributes.enable section.
// The user can specify the Prometheus or OTEL notation, and can include or not
// the units and aggregations for the metrics. Beyla will accept all the inputs
// as long as the metric name is recorgnisable.
func normalizeMetric(name attrobi.Section) attrobi.Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".ratio", ".bucket", ".sum", ".count", ".total"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	for _, suffix := range []string{".bytes", ".seconds"} {
		if strings.HasSuffix(nameStr, suffix) {
			nameStr = nameStr[:len(nameStr)-len(suffix)]
			break
		}
	}
	return attrobi.Section(nameStr)
}
