package otel

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/exp/slog"

	"github.com/grafana/http-autoinstrument/pkg/transform"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
)

const reporterName = "github.com/grafana/http-autoinstrument"

type TracesConfig struct {
	ServiceName    string `yaml:"service_name" env:"SERVICE_NAME"`
	Endpoint       string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m TracesConfig) Enabled() bool {
	return m.Endpoint != "" || m.TracesEndpoint != ""
}

type TracesReporter struct {
	traceExporter *otlptrace.Exporter
	traceProvider *trace.TracerProvider
}

func TracesReporterProvider(cfg TracesConfig) node.TerminalFunc[transform.HTTPRequestSpan] {
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}
	tr, err := newTracesReporter(cfg.ServiceName, endpoint)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces
}

func newTracesReporter(svcName, endpoint string) (*TracesReporter, error) {
	ctx := context.TODO()

	r := TracesReporter{}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(svcName),
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

	r.traceProvider = trace.NewTracerProvider(
		trace.WithResource(resources),
		trace.WithSyncer(r.traceExporter),
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

func (r *TracesReporter) reportTraces(spans <-chan transform.HTTPRequestSpan) {
	defer r.close()
	tracer := r.traceProvider.Tracer(reporterName)
	for span := range spans {
		// TODO: there must be a better way to instantiate spans
		_, sp := tracer.Start(context.TODO(), "session",
			trace2.WithTimestamp(span.Start),
			trace2.WithAttributes(
				semconv.HTTPMethod(span.Method),
				semconv.HTTPStatusCode(span.Status),
				semconv.HTTPTarget(span.Path),
				// TODO: add src/dst ip and dst port
			),
			// TODO: trace2.WithSpanKind()
		)
		sp.End(trace2.WithTimestamp(span.End))
	}
}
