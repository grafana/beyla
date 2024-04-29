package metricname

// Normal metric names use the dot.notation and suppress any .total .sum .count suffix
type Normal string

const (
	NormalBeylaNetworkFlows = Normal("beyla.network.flow.bytes")
)

// OTEL metrics define the names as being exposed by OpenTelemetry exporters

const (
	OTELBeylaNetworkFlows = string(NormalBeylaNetworkFlows) + ".total"
)

// Prom metrics define the names as being exposed by Prometheus exporter

const (
	PromBeylaNetworkFlows = "beyla_network_flow_bytes_total"
)
