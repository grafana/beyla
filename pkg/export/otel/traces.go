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
	ReqSpan transform.HTTPRequestSpan
	RootCtx context.Context
}

var topSpans, _ = lru.New[uint64, SessionSpan](8192)
var clientSpans, _ = lru.New[uint64, []transform.HTTPRequestSpan](8192)

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
	case transform.EventTypeGRPCClient:
		return []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			semconv.NetPeerName(span.Host),
			semconv.NetPeerPort(span.HostPort),
		}
	}
	return []attribute.KeyValue{}
}

func traceName(span *transform.HTTPRequestSpan) string {
	switch span.Type {
	case transform.EventTypeHTTP:
		name := span.Method
		if span.Route != "" {
			name += " " + span.Route
		}
		return name
	case transform.EventTypeGRPC, transform.EventTypeGRPCClient:
		return span.Path
	case transform.EventTypeHTTPClient:
		return span.Method
	}
	return ""
}

func spanKind(span *transform.HTTPRequestSpan) trace2.SpanKind {
	switch span.Type {
	case transform.EventTypeHTTP, transform.EventTypeGRPC:
		return trace2.SpanKindServer
	case transform.EventTypeHTTPClient, transform.EventTypeGRPCClient:
		return trace2.SpanKindClient
	}
	return trace2.SpanKindInternal
}

func makeSpan(parentCtx context.Context, tracer trace2.Tracer, span *transform.HTTPRequestSpan) SessionSpan {
	reqStart, start, end := span.Timings()

	// Create a parent span for the whole request session
	ctx, sp := tracer.Start(parentCtx, traceName(span),
		trace2.WithTimestamp(reqStart),
		trace2.WithSpanKind(spanKind(span)),
		trace2.WithAttributes(traceAttributes(span)...),
	)

	if span.RequestStart != span.Start {
		var spP trace2.Span

		// Create a child span showing the queue time
		_, spQ := tracer.Start(ctx, "in queue",
			trace2.WithTimestamp(reqStart),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spQ.End(trace2.WithTimestamp(start))

		// Create a child span showing the processing time
		// Override the active context for the span to be the processing span
		ctx, spP = tracer.Start(ctx, "processing",
			trace2.WithTimestamp(start),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spP.End(trace2.WithTimestamp(end))
	}

	sp.End(trace2.WithTimestamp(end))

	return SessionSpan{*span, ctx}
}

func (r *TracesReporter) reportClientSpan(span *transform.HTTPRequestSpan, tracer trace2.Tracer) {
	ctx := context.TODO()

	// we have a parent request span
	if span.ID != 0 {
		sp, ok := topSpans.Get(span.ID)
		if ok && span.Inside(&sp.ReqSpan) {
			// parent span exists, use it
			ctx = sp.RootCtx
		} else {
			// stash the client span for later addition
			cs, ok := clientSpans.Get(span.ID)
			if !ok {
				cs = []transform.HTTPRequestSpan{*span}
			} else {
				cs = append(cs, *span)
			}
			clientSpans.Add(span.ID, cs)

			// don't add the span just yet, the parent span isn't ready
			return
		}
	}

	makeSpan(ctx, tracer, span)
}

func (r *TracesReporter) reportServerSpan(span *transform.HTTPRequestSpan, tracer trace2.Tracer) {
	s := makeSpan(context.TODO(), tracer, span)
	topSpans.Add(span.ID, s)
	cs, ok := clientSpans.Get(span.ID)
	newer := []transform.HTTPRequestSpan{}
	if ok {
		// finish any client spans that were waiting for this parent span
		for j := range cs {
			cspan := &cs[j]
			if cspan.Inside(span) {
				makeSpan(s.RootCtx, tracer, cspan)
			} else if cspan.Start > span.RequestStart {
				newer = append(newer, *cspan)
			} else {
				makeSpan(context.TODO(), tracer, cspan)
			}
		}
		if len(newer) == 0 {
			clientSpans.Remove(span.ID)
		} else {
			clientSpans.Add(span.ID, newer)
		}
	}
}

func (r *TracesReporter) reportTraces(input <-chan []transform.HTTPRequestSpan) {
	defer r.close()
	tracer := r.traceProvider.Tracer(reporterName)
	for spans := range input {
		for i := range spans {
			span := &spans[i]

			switch span.Type {
			case transform.EventTypeHTTPClient, transform.EventTypeGRPCClient:
				r.reportClientSpan(span, tracer)
			case transform.EventTypeHTTP, transform.EventTypeGRPC:
				r.reportServerSpan(span, tracer)
			}
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
