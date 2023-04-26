package otel

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
)

type SessionSpan struct {
	Session trace2.Span
	SubSpan trace2.Span
	RootCtx context.Context
}

var l, _ = lru.New[uint64, SessionSpan](8192)

const reporterName = "github.com/grafana/ebpf-autoinstrument"

type TracesConfig struct {
	ServiceName    string `yaml:"service_name" env:"OTEL_SERVICE_NAME"`
	Endpoint       string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	// Configuration options below this line will remain undocumented at the moment,
	// but can be useful for performance-tuning of some customers.

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
	tr, err := newTracesReporter(&cfg)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces
}

func newTracesReporter(cfg *TracesConfig) (*TracesReporter, error) {
	ctx := context.TODO()

	r := TracesReporter{}

	// TODO: make configurable
	resources := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(cfg.ServiceName),
	)

	// Instantiate the OTLP HTTP traceExporter
	topts, err := getTracesEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	r.traceExporter, err = otlptracehttp.New(ctx, topts...)
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
	case transform.EventTypeHTTPClient:
		return []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPURL(span.Path),
			semconv.NetPeerName(span.Host),
			semconv.NetPeerPort(span.HostPort),
			semconv.HTTPRequestContentLength(int(span.ContentLength)),
		}
	}
	return []attribute.KeyValue{}
}

func traceName(span *transform.HTTPRequestSpan) string {
	switch span.Type {
	case transform.EventTypeHTTP, transform.EventTypeHTTPStart, transform.EventTypeGRPC:
		return "session"
	case transform.EventTypeHTTPClient:
		return "request"
	}
	return ""
}

func spanKind(span *transform.HTTPRequestSpan) trace2.SpanKind {
	switch span.Type {
	case transform.EventTypeHTTP, transform.EventTypeHTTPStart, transform.EventTypeGRPC:
		return trace2.SpanKindServer
	case transform.EventTypeHTTPClient:
		return trace2.SpanKindClient
	}
	return trace2.SpanKindInternal
}

func makeSpan(parentCtx context.Context, tracer trace2.Tracer, span *transform.HTTPRequestSpan) SessionSpan {
	var spP trace2.Span
	// Create a parent span for the whole request session
	ctx, sp := tracer.Start(parentCtx, traceName(span),
		trace2.WithTimestamp(span.RequestStart),
		trace2.WithSpanKind(spanKind(span)),
	)

	if span.RequestStart != span.Start {
		// Create a child span showing the queue time
		_, spQ := tracer.Start(ctx, "in queue",
			trace2.WithTimestamp(span.RequestStart),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spQ.End(trace2.WithTimestamp(span.Start))

		// Create a child span showing the processing time
		// Override the active context for the span to be the processing span
		ctx, spP = tracer.Start(ctx, "processing",
			trace2.WithTimestamp(span.Start),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
	}

	return SessionSpan{sp, spP, ctx}
}

func (r *TracesReporter) reportTraces(input <-chan []transform.HTTPRequestSpan) {
	defer r.close()
	tracer := r.traceProvider.Tracer(reporterName)
	for spans := range input {
		for i := range spans {
			if spans[i].Type == transform.EventTypeHTTPStart {
				l.Add(spans[i].ID, makeSpan(context.TODO(), tracer, &spans[i]))
				continue
			}

			var s SessionSpan
			attrs := traceAttributes(&spans[i])

			if spans[i].Type == transform.EventTypeHTTPClient {
				ctx := context.TODO()

				sp, ok := l.Get(spans[i].ID)
				if ok {
					ctx = sp.RootCtx
				}
				s = makeSpan(ctx, tracer, &spans[i])
			} else {
				cached, ok := l.Get(spans[i].ID)
				if !ok {
					s = makeSpan(context.TODO(), tracer, &spans[i])
				} else {
					s = cached
					l.Remove(spans[i].ID)
				}
			}

			s.Session.SetAttributes(attrs...)
			if s.SubSpan != nil {
				s.SubSpan.End(trace2.WithTimestamp(spans[i].End))
			}
			s.Session.End(trace2.WithTimestamp(spans[i].End))
		}
	}
}

func getTracesEndpointOptions(cfg *TracesConfig) ([]otlptracehttp.Option, error) {
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if len(murl.Path) > 0 && murl.Path != "/" && !strings.HasSuffix(murl.Path, "/v1/traces") {
		opts = append(opts, otlptracehttp.WithURLPath(murl.Path+"/v1/traces"))
	}

	return opts, nil
}
