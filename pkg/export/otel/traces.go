package otel

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
)

const reporterName = "github.com/grafana/ebpf-autoinstrument"

type TracesConfig struct {
	ServiceName        string        `yaml:"service_name" env:"SERVICE_NAME"`
	Endpoint           string        `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint     string        `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`
	MaxExportBatchSize int           `yaml:"max_export_batch_size" env:"OTLP_TRACES_MAX_EXPORT_BATCH_SIZE"`
	MaxQueueSize       int           `yaml:"max_queue_size" env:"OTLP_TRACES_MAX_QUEUE_SIZE"`
	BatchTimeout       time.Duration `yaml:"batch_timeout" env:"OTLP_TRACES_BATCH_TIMEOUT"`
	ExportTimeout      time.Duration `yaml:"export_timeout" env:"OTLP_TRACES_EXPORT_TIMEOUT"`
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m TracesConfig) Enabled() bool { //nolint:gocritic
	return m.Endpoint != "" || m.TracesEndpoint != ""
}

type TracesReporter struct {
	traceExporter *otlptrace.Exporter
	traceProvider *trace.TracerProvider
}

func TracesReporterProvider(cfg TracesConfig) node.TerminalFunc[[]transform.HTTPRequestSpan] { //nolint:gocritic
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}
	tr, err := newTracesReporter(&cfg, endpoint)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces
}

func newTracesReporter(cfg *TracesConfig, endpoint string) (*TracesReporter, error) {
	ctx := context.TODO()

	r := TracesReporter{}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(cfg.ServiceName),
	)

	// Instantiate the OTLP HTTP traceExporter
	// TODO: better use GRPC (secure)
	var err error
	// TODO: allow configuring auth headers and secure/insecure connections
	r.traceExporter, err = otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // TODO: configurable
	)
	if err != nil {
		return nil, fmt.Errorf("creating trace exporter: %w", err)
	}

	var opts []trace.BatchSpanProcessorOption
	if cfg.MaxExportBatchSize > 0 {
		opts = append(opts, trace.WithMaxExportBatchSize(cfg.MaxExportBatchSize))
	}
	if cfg.MaxQueueSize > 0 {
		opts = append(opts, trace.WithMaxQueueSize(cfg.MaxQueueSize))
	}
	if cfg.BatchTimeout > 0 {
		opts = append(opts, trace.WithBatchTimeout(cfg.BatchTimeout))
	}
	if cfg.ExportTimeout > 0 {
		opts = append(opts, trace.WithExportTimeout(cfg.ExportTimeout))
	}

	bsp := trace.NewBatchSpanProcessor(r.traceExporter, opts...)
	r.traceProvider = trace.NewTracerProvider(
		trace.WithResource(resources),
		trace.WithSpanProcessor(bsp),
		//trace.WithSampler(trace.AlwaysSample()),
	)

	return &r, nil
}

func (r *TracesReporter) close() {
	if err := r.traceProvider.Shutdown(context.TODO()); err != nil {
		slog.With("component", "TracesReporter").Error("closing traces provider", err)
	}
	if err := r.traceExporter.Shutdown(context.TODO()); err != nil {
		slog.With("component", "TracesReporter").Error("closing traces exporter", err)
	}
}

func traceAttributes(span *transform.HTTPRequestSpan) []attribute.KeyValue {
	switch span.Type {
	case transform.EventTypeHTTP:
		attrs := []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPTarget(span.Path),
			semconv.NetSockPeerAddr(span.Peer),
			semconv.NetHostName(span.Host),
			semconv.NetHostPort(span.HostPort),
			semconv.HTTPRequestContentLength(int(span.ContentLength)),
		}
		if span.Route != "" {
			attrs = append(attrs, semconv.HTTPRoute(span.Route))
		}
		return attrs
	case transform.EventTypeGRPC:
		return []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			semconv.NetSockPeerAddr(span.Peer),
			semconv.NetHostName(span.Host),
			semconv.NetHostPort(span.HostPort),
		}
	}
	return []attribute.KeyValue{}
}

func (r *TracesReporter) reportTraces(input <-chan []transform.HTTPRequestSpan) {
	defer r.close()
	tracer := r.traceProvider.Tracer(reporterName)
	for spans := range input {
		for i := range spans {
			attrs := traceAttributes(&spans[i])

			// Create a parent span for the whole request session
			ctx, sp := tracer.Start(context.TODO(), "session",
				trace2.WithTimestamp(spans[i].RequestStart),
				trace2.WithAttributes(attrs...),
				trace2.WithSpanKind(trace2.SpanKindInternal),
			)

			// Create a child span showing the queue time
			_, spQ := tracer.Start(ctx, "in queue",
				trace2.WithTimestamp(spans[i].RequestStart),
				trace2.WithSpanKind(trace2.SpanKindInternal),
			)
			spQ.End(trace2.WithTimestamp(spans[i].Start))

			// Create a child span showing the processing time
			_, spP := tracer.Start(ctx, "processing",
				trace2.WithTimestamp(spans[i].Start),
				trace2.WithSpanKind(trace2.SpanKindInternal),
			)
			spP.End(trace2.WithTimestamp(spans[i].End))

			sp.End(trace2.WithTimestamp(spans[i].End))
		}
	}
}
