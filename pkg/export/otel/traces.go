package otel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"
	"golang.org/x/exp/slog"
	"google.golang.org/grpc/credentials"

	"github.com/grafana/ebpf-autoinstrument/pkg/imetrics"
	"github.com/grafana/ebpf-autoinstrument/pkg/pipe/global"
	"github.com/grafana/ebpf-autoinstrument/pkg/transform"
)

func log() *slog.Logger {
	return slog.With("component", "otel.TracesReporter")
}

type SessionSpan struct {
	ReqSpan transform.HTTPRequestSpan
	RootCtx context.Context
}

var topSpans, _ = lru.New[uint64, SessionSpan](8192)
var clientSpans, _ = lru.New[uint64, []transform.HTTPRequestSpan](8192)
var namedTracers, _ = lru.New[string, *trace.TracerProvider](512)

const reporterName = "github.com/grafana/ebpf-autoinstrument"

type TracesConfig struct {
	ServiceName      string `yaml:"service_name" env:"OTEL_SERVICE_NAME"`
	ServiceNamespace string `yaml:"service_namespace" env:"SERVICE_NAMESPACE"`

	Endpoint       string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	// TODO: Protocol will remain undocumented until we support it also in the metrics exporter.
	Protocol       Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	TracesProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_INSECURE_SKIP_VERIFY"`

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

func (m *TracesConfig) GetProtocol() Protocol {
	if m.TracesProtocol != "" {
		return m.TracesProtocol
	}
	return m.Protocol
}

type TracesReporter struct {
	ctx           context.Context
	traceExporter trace.SpanExporter
	traceProvider *trace.TracerProvider
	bsp           trace.SpanProcessor
}

func TracesReporterProvider(ctx context.Context, cfg TracesConfig) (node.TerminalFunc[[]transform.HTTPRequestSpan], error) { //nolint:gocritic
	tr, err := newTracesReporter(ctx, &cfg)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces, nil
}

func newTracesReporter(ctx context.Context, cfg *TracesConfig) (*TracesReporter, error) {
	log := log()
	r := TracesReporter{ctx: ctx}

	// Instantiate the OTLP HTTP or GRPC traceExporter
	var err error
	var exporter trace.SpanExporter
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		log.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		if exporter, err = httpTracer(ctx, cfg); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL HTTP traces exporter: %w", err)
		}
	case ProtocolGRPC:
		log.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		if exporter, err = grpcTracer(ctx, cfg); err != nil {
			return nil, fmt.Errorf("can't instantiate OTEL GRPC traces exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf)
	}

	r.traceExporter = instrumentTraceExporter(ctx, exporter)

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

	resource := otelResource(ctx, cfg.ServiceName, cfg.ServiceNamespace)
	r.bsp = trace.NewBatchSpanProcessor(r.traceExporter, opts...)
	r.traceProvider = trace.NewTracerProvider(
		trace.WithResource(resource),
		trace.WithSpanProcessor(r.bsp),
	)

	return &r, nil
}

func httpTracer(ctx context.Context, cfg *TracesConfig) (*otlptrace.Exporter, error) {
	topts, err := getHTTPTracesEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	texp, err := otlptracehttp.New(ctx, topts...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP trace exporter: %w", err)
	}
	return texp, nil
}

func grpcTracer(ctx context.Context, cfg *TracesConfig) (*otlptrace.Exporter, error) {
	topts, err := getGRPCTracesEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	texp, err := otlptracegrpc.New(ctx, topts...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP trace exporter: %w", err)
	}
	return texp, nil
}

// instrumentTraceExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed traces exporter inside an instrumented exporter
func instrumentTraceExporter(ctx context.Context, in trace.SpanExporter) trace.SpanExporter {
	internalMetrics := global.Context(ctx).Metrics
	// avoid wrapping the instrumented exporter if we don't have
	// internal instrumentation (NoopReporter)
	if _, ok := internalMetrics.(imetrics.NoopReporter); ok || internalMetrics == nil {
		return in
	}
	return &instrumentedTracesExporter{
		SpanExporter: in,
		internal:     internalMetrics,
	}
}

func (r *TracesReporter) close() {
	if err := r.traceProvider.Shutdown(r.ctx); err != nil {
		slog.With("component", "TracesReporter").Error("closing traces provider", err)
	}
	if err := r.traceExporter.Shutdown(r.ctx); err != nil {
		slog.With("component", "TracesReporter").Error("closing traces exporter", err)
	}
}

func (r *TracesReporter) traceAttributes(span *transform.HTTPRequestSpan) []attribute.KeyValue {
	var attrs []attribute.KeyValue

	switch span.Type {
	case transform.EventTypeHTTP:
		attrs = []attribute.KeyValue{
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
	case transform.EventTypeGRPC:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			semconv.NetSockPeerAddr(span.Peer),
			semconv.NetHostName(span.Host),
			semconv.NetHostPort(span.HostPort),
		}
	case transform.EventTypeHTTPClient:
		attrs = []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPURL(span.Path),
			semconv.NetPeerName(span.Host),
			semconv.NetPeerPort(span.HostPort),
			semconv.HTTPRequestContentLength(int(span.ContentLength)),
		}
	case transform.EventTypeGRPCClient:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			semconv.NetPeerName(span.Host),
			semconv.NetPeerPort(span.HostPort),
		}
	}

	if span.ServiceName != "" { // we don't have service name set, system wide instrumentation
		attrs = append(attrs, semconv.ServiceName(span.ServiceName))
	}

	return attrs
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

func (r *TracesReporter) makeSpan(parentCtx context.Context, tracer trace2.Tracer, span *transform.HTTPRequestSpan) SessionSpan {
	t := span.Timings()

	// Create a parent span for the whole request session
	ctx, sp := tracer.Start(parentCtx, traceName(span),
		trace2.WithTimestamp(t.RequestStart),
		trace2.WithSpanKind(spanKind(span)),
		trace2.WithAttributes(r.traceAttributes(span)...),
	)

	if span.RequestStart != span.Start {
		var spP trace2.Span

		// Create a child span showing the queue time
		_, spQ := tracer.Start(ctx, "in queue",
			trace2.WithTimestamp(t.RequestStart),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spQ.End(trace2.WithTimestamp(t.Start))

		// Create a child span showing the processing time
		// Override the active context for the span to be the processing span
		ctx, spP = tracer.Start(ctx, "processing",
			trace2.WithTimestamp(t.Start),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spP.End(trace2.WithTimestamp(t.End))
	}

	sp.End(trace2.WithTimestamp(t.End))

	return SessionSpan{*span, ctx}
}

func (r *TracesReporter) reportClientSpan(span *transform.HTTPRequestSpan, tracer trace2.Tracer) {
	ctx := r.ctx

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

	r.makeSpan(ctx, tracer, span)
}

func (r *TracesReporter) reportServerSpan(span *transform.HTTPRequestSpan, tracer trace2.Tracer) {

	s := r.makeSpan(r.ctx, tracer, span)
	if span.ID != 0 {
		topSpans.Add(span.ID, s)
		cs, ok := clientSpans.Get(span.ID)
		newer := []transform.HTTPRequestSpan{}
		if ok {
			// finish any client spans that were waiting for this parent span
			for j := range cs {
				cspan := &cs[j]
				if cspan.Inside(span) {
					r.makeSpan(s.RootCtx, tracer, cspan)
				} else if cspan.Start > span.RequestStart {
					newer = append(newer, *cspan)
				} else {
					r.makeSpan(r.ctx, tracer, cspan)
				}
			}
			if len(newer) == 0 {
				clientSpans.Remove(span.ID)
			} else {
				clientSpans.Add(span.ID, newer)
			}
		}
	}
}

func (r *TracesReporter) reportTraces(input <-chan []transform.HTTPRequestSpan) {
	defer r.close()
	defaultTracer := r.traceProvider.Tracer(reporterName)
	for spans := range input {
		for i := range spans {
			spanTracer := defaultTracer
			span := &spans[i]

			if span.ServiceName != "" {
				spanTracer = r.namedTracer(span.ServiceName)
			}

			switch span.Type {
			case transform.EventTypeHTTPClient, transform.EventTypeGRPCClient:
				r.reportClientSpan(span, spanTracer)
			case transform.EventTypeHTTP, transform.EventTypeGRPC:
				r.reportServerSpan(span, spanTracer)
			}
		}
	}
}

func (r *TracesReporter) namedTracer(comm string) trace2.Tracer {
	traceProvider, ok := namedTracers.Get(comm)

	if !ok {
		resource := otelResource(r.ctx, comm, "")
		traceProvider = trace.NewTracerProvider(
			trace.WithResource(resource),
			trace.WithSpanProcessor(r.bsp),
		)
		namedTracers.Add(comm, traceProvider)
	}

	return traceProvider.Tracer(reporterName)
}

func parseEndpoint(cfg *TracesConfig) (*url.URL, error) {
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, nil
}

func getHTTPTracesEndpointOptions(cfg *TracesConfig) ([]otlptracehttp.Option, error) {
	log := log().With("transport", "http")

	murl, err := parseEndpoint(cfg)
	if err != nil {
		return nil, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	setProtocol(cfg)
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts = append(opts, otlptracehttp.WithInsecure())
	}

	if len(murl.Path) > 0 && murl.Path != "/" && !strings.HasSuffix(murl.Path, "/v1/traces") {
		urlPath := murl.Path + "/v1/traces"
		log.Debug("Specifying path", "path", urlPath)
		opts = append(opts, otlptracehttp.WithURLPath(urlPath))
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}

	return opts, nil
}

func getGRPCTracesEndpointOptions(cfg *TracesConfig) ([]otlptracegrpc.Option, error) {
	log := log().With("transport", "grpc")
	murl, err := parseEndpoint(cfg)
	if err != nil {
		return nil, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	setProtocol(cfg)
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(murl.Host),
	}
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	}

	return opts, nil
}

// HACK: at the time of writing this, the otelptracehttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelptracehttp.WithProtocol is supported
func setProtocol(cfg *TracesConfig) {
	if _, ok := os.LookupEnv(envTracesProtocol); ok {
		return
	}
	if _, ok := os.LookupEnv(envProtocol); ok {
		return
	}
	if cfg.TracesProtocol != "" {
		os.Setenv(envTracesProtocol, string(cfg.TracesProtocol))
		return
	}
	if cfg.Protocol != "" {
		os.Setenv(envProtocol, string(cfg.Protocol))
	}
}
