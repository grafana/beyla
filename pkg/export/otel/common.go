package otel

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"

	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
)

// Protocol values for the OTEL_EXPORTER_OTLP_PROTOCOL, OTEL_EXPORTER_OTLP_TRACES_PROTOCOL and
// OTEL_EXPORTER_OTLP_METRICS_PROTOCOL standard configuration values
// More info: https://opentelemetry.io/docs/concepts/sdk-configuration/otlp-exporter-configuration/
type Protocol string

const (
	ProtocolGRPC         Protocol = "grpc"
	ProtocolHTTPProtobuf Protocol = "http/protobuf"
	ProtocolHTTPJSON     Protocol = "http/json"
)

const (
	envTracesProtocol  = "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"
	envMetricsProtocol = "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"
	envProtocol        = "OTEL_EXPORTER_OTLP_PROTOCOL"
)

// Buckets defines the histograms bucket boundaries, and allows users to
// redefine them
type Buckets struct {
	DurationHistogram    []float64 `yaml:"duration_histogram"`
	RequestSizeHistogram []float64 `yaml:"request_size_histogram"`
}

var DefaultBuckets = Buckets{
	// Default values as specified in the OTEL specification
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/metrics/semantic_conventions/http-metrics.md
	DurationHistogram: []float64{0, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1, 2.5, 5, 7.5, 10},

	RequestSizeHistogram: []float64{0, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192},
}

// TODO: when we join both traces' and metrics ServiceName and ServiceNamespace into a common configuration section
// provide a unique Resource for both metrics and traces reporter
func otelResource(ctx context.Context, cfgSvcName, cfgSvcNamespace string) *resource.Resource {
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	svcName := cfgSvcName
	if svcName == "" {
		svcName = global.Context(ctx).ServiceName
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(svcName),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces_target_info metric,
		// so the service is visible in the ServicesList
		// This attribute also allows that App O11y plugin shows this app as a Go application.
		// TODO: detect the runtime of the target executable and set this value accordingly
		semconv.TelemetrySDKLanguageGo,
	}

	if cfgSvcNamespace != "" {
		attrs = append(attrs, semconv.ServiceNamespace(cfgSvcNamespace))
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}
