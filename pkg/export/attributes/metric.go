package attributes

import "strings"

// Section of the attributes.select configuration. They are metric names
// using the dot.notation and suppressing any .total .sum or .count suffix.
// They are used as a standardized key in the attributes.select map, whichever
// metric format or name the user provides.
type Section string

// Name of a metric in three forms
type Name struct {
	// Section name in the attributes.select configuration option. It is
	// a normalized form accorting to the normalizeMetric function below.
	// It makes sure that it does not have metric nor aggregation suffix.
	Section Section
	// Prom name of a metric for the Prometheus exporter
	Prom string
	// OTEL name of a metric for the OTEL exporter
	OTEL string
}

var (
	BeylaNetworkFlow = Name{
		Section: "beyla.network.flow",
		Prom:    "beyla_network_flow_bytes_total",
		OTEL:    "beyla.network.flow.bytes",
	}
	HTTPServerRequestSize = Name{
		Section: "http.server.request.body.size",
		Prom:    "http_server_request_body_size_bytes",
		OTEL:    "http.server.request.body.size",
	}
	HTTPClientRequestSize = Name{
		Section: "http.client.request.body.size",
		Prom:    "http_client_request_body_size_bytes",
		OTEL:    "http.client.request.body.size",
	}
	HTTPServerDuration = Name{
		Section: "http.server.request.duration",
		Prom:    "http_server_request_duration_seconds",
		OTEL:    "http.server.request.duration",
	}
	HTTPClientDuration = Name{
		Section: "http.client.request.duration",
		Prom:    "http_client_request_duration_seconds",
		OTEL:    "http.client.request.duration",
	}
	RPCServerDuration = Name{
		Section: "rpc.server.duration",
		Prom:    "rpc_server_duration_seconds",
		OTEL:    "rpc.server.duration",
	}
	RPCClientDuration = Name{
		Section: "rpc.client.duration",
		Prom:    "rpc_client_duration_seconds",
		OTEL:    "rpc.client.duration",
	}
	DBClientDuration = Name{
		Section: "db.client.operation.duration",
		Prom:    "db_client_operation_duration_seconds",
		OTEL:    "db.client.operation.duration",
	}
	ProcessCPUTime = Name{
		Section: "process.cpu.time",
		Prom:    "process_cpu_time_seconds_total",
		OTEL:    "process.cpu.time",
	}
	ProcessCPUUtilization = Name{
		Section: "process.cpu.utilization",
		Prom:    "process_cpu_utilization_ratio",
		OTEL:    "process.cpu.utilization",
	}
	ProcessMemoryUsage = Name{
		Section: "process.memory.usage",
		Prom:    "process_memory_usage_bytes",
		OTEL:    "process.memory.usage",
	}
	ProcessMemoryVirtual = Name{
		Section: "process.memory.virtual",
		Prom:    "process_memory_virtual_bytes",
		OTEL:    "process.memory.virtual",
	}
	ProcessDiskIO = Name{
		Section: "process.disk.io",
		Prom:    "process_disk_io_bytes_total",
		OTEL:    "process.disk.io",
	}
	ProcessNetIO = Name{
		Section: "process.network.io",
		Prom:    "process_network_io_bytes_total",
		OTEL:    "process.network.io",
	}
	MessagingPublishDuration = Name{
		Section: "messaging.publish.duration",
		Prom:    "messaging_publish_duration_seconds",
		OTEL:    "messaging.publish.duration",
	}
	MessagingProcessDuration = Name{
		Section: "messaging.process.duration",
		Prom:    "messaging_process_duration_seconds",
		OTEL:    "messaging.process.duration",
	}
	GPUKernelLaunchCalls = Name{
		Section: "gpu.kernel.launch.calls",
		Prom:    "gpu_kernel_launch_calls_total",
		OTEL:    "gpu.kernel.launch.calls",
	}
)

// normalizeMetric will facilitate the user-input in the attributes.enable section.
// The user can specify the Prometheus or OTEL notation, and can include or not
// the units and aggregations for the metrics. Beyla will accept all the inputs
// as long as the metric name is recorgnisable.
func normalizeMetric(name Section) Section {
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
	return Section(nameStr)
}
