package extraattributes

import (
	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
)

var (
	ProcessCPUTime = attributes.Name{
		Section: "process.cpu.time",
		Prom:    "process_cpu_time_seconds_total",
		OTEL:    "process.cpu.time",
	}
	ProcessCPUUtilization = attributes.Name{
		Section: "process.cpu.utilization",
		Prom:    "process_cpu_utilization_ratio",
		OTEL:    "process.cpu.utilization",
	}
	ProcessMemoryUsage = attributes.Name{
		Section: "process.memory.usage",
		Prom:    "process_memory_usage_bytes",
		OTEL:    "process.memory.usage",
	}
	ProcessMemoryVirtual = attributes.Name{
		Section: "process.memory.virtual",
		Prom:    "process_memory_virtual_bytes",
		OTEL:    "process.memory.virtual",
	}
	ProcessDiskIO = attributes.Name{
		Section: "process.disk.io",
		Prom:    "process_disk_io_bytes_total",
		OTEL:    "process.disk.io",
	}
	ProcessNetIO = attributes.Name{
		Section: "process.network.io",
		Prom:    "process_network_io_bytes_total",
		OTEL:    "process.network.io",
	}
)
