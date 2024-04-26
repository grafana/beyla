package metric

import "strings"

// Section of the attributes.select configuration. They are metric names
// using the dot.notation and suppressing any .total .sum or .count suffix.
// They are used as a standardized key in the attributes.select map, whichever
// metric format or name the user provides.
type Section string

type Name struct {
	// Section name in the attributes.select configuration option. It is
	// a normalized form accorting to the normalizeMetric function below.
	// It makes sure that it does not have metric nor aggregation suffix.
	Section Section
	Prom    string
	OTEL    string
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
	SQLClientDuration = Name{
		Section: "sql.client.duration",
		Prom:    "sql_client_duration_seconds",
		OTEL:    "sql.client.duration",
	}
)

func normalizeMetric(name Section) Section {
	nameStr := strings.ReplaceAll(string(name), "_", ".")
	for _, suffix := range []string{".bucket", ".sum", ".count", ".total"} {
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
