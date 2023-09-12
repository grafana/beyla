package otel

import (
	"fmt"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
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

func otelResource(svcName, cfgSvcNamespace string) *resource.Resource {
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

// ReporterPool keeps an LRU cache of different OTEL reporters given a service name.
// TODO: evict reporters after a time without being accessed
type ReporterPool[T any] struct {
	pool *simplelru.LRU[string, T]

	itemConstructor func(string) (T, error)
}

// NewReporterPool creates a ReporterPool instance given a cache length,
// an eviction callback to be invoked each time an element is removed
// from the cache, and a constructor function that will specify how to
// instantiate the generic OTEL metrics/traces reporter.
func NewReporterPool[T any](
	cacheLen int,
	callback simplelru.EvictCallback[string, T],
	itemConstructor func(string) (T, error),
) ReporterPool[T] {
	pool, _ := simplelru.NewLRU[string, T](cacheLen, callback)
	return ReporterPool[T]{pool: pool, itemConstructor: itemConstructor}
}

// For retrieves the associated item for the given service name, or
// creates a new one if it does not exist
func (rp *ReporterPool[T]) For(svcName string) (T, error) {
	if m, ok := rp.pool.Get(svcName); ok {
		return m, nil
	}
	m, err := rp.itemConstructor(svcName)
	if err != nil {
		var t T
		return t, fmt.Errorf("creating resource for service %q: %w", svcName, err)
	}
	rp.pool.Add(svcName, m)
	return m, nil
}
