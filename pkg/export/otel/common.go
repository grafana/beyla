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
