package otel

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

func tlog() *slog.Logger {
	return slog.With("component", "otel.TracesReporter")
}

type SessionSpan struct {
	ReqSpan request.Span
	RootCtx context.Context
}

// TODO: global variables, move as fields of TracesReporter
var topSpans, _ = lru.New[uint64, SessionSpan](8192)
var clientSpans, _ = lru.New[uint64, []request.Span](8192)

const reporterName = "github.com/grafana/beyla"

type TracesConfig struct {
	CommonEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	Protocol       Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	TracesProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_INSECURE_SKIP_VERIFY"`

	SamplingRatio float64 `yaml:"sampling_ratio" env:"OTEL_TRACE_SAMPLING_RATIO"`

	// Configuration options below this line will remain undocumented at the moment,
	// but can be useful for performance-tuning of some customers.
	MaxExportBatchSize int           `yaml:"max_export_batch_size" env:"OTLP_TRACES_MAX_EXPORT_BATCH_SIZE"`
	MaxQueueSize       int           `yaml:"max_queue_size" env:"OTLP_TRACES_MAX_QUEUE_SIZE"`
	BatchTimeout       time.Duration `yaml:"batch_timeout" env:"OTLP_TRACES_BATCH_TIMEOUT"`
	ExportTimeout      time.Duration `yaml:"export_timeout" env:"OTLP_TRACES_EXPORT_TIMEOUT"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"METRICS_REPORT_CACHE_LEN"`
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m TracesConfig) Enabled() bool { //nolint:gocritic
	return m.CommonEndpoint != "" || m.TracesEndpoint != ""
}

func (m *TracesConfig) GetProtocol() Protocol {
	if m.TracesProtocol != "" {
		return m.TracesProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.GuessProtocol()
}

func (m *TracesConfig) GuessProtocol() Protocol {
	// If no explicit protocol is set, we guess it it from the metrics enpdoint port
	// (assuming it uses a standard port or a development-like form like 14317, 24317, 14318...)
	ep, _, err := parseTracesEndpoint(m)
	if err == nil {
		if strings.HasSuffix(ep.Port(), UsualPortGRPC) {
			return ProtocolGRPC
		} else if strings.HasSuffix(ep.Port(), UsualPortHTTP) {
			return ProtocolHTTPProtobuf
		}
	}
	// Otherwise we return default protocol according to the latest specification:
	// https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/protocol/exporter.md?plain=1#L53
	return ProtocolHTTPProtobuf
}

// TracesReporter implement the graph node that receives request.Span
// instances and forwards them as OTEL traces.
type TracesReporter struct {
	ctx           context.Context
	cfg           *TracesConfig
	traceExporter trace.SpanExporter
	bsp           trace.SpanProcessor
	// TODO: at some point we might want to set a namespace per service
	namespace string
	reporters ReporterPool[*Tracers]
}

// Tracers handles the OTEL traces providers and exporters.
// There is a Tracers instance for each instrumented service/process.
type Tracers struct {
	provider *trace.TracerProvider
	tracer   trace2.Tracer
}

func ReportTraces(ctx context.Context, cfg *TracesConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]request.Span], error) {
	tr, err := newTracesReporter(ctx, cfg, ctxInfo)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces, nil
}

func newTracesReporter(ctx context.Context, cfg *TracesConfig, ctxInfo *global.ContextInfo) (*TracesReporter, error) {
	log := tlog()
	r := TracesReporter{ctx: ctx, cfg: cfg, namespace: ctxInfo.ServiceNamespace}
	r.reporters = NewReporterPool[*Tracers](cfg.ReportersCacheLen,
		func(k string, v *Tracers) {
			llog := log.With("serviceName", k)
			llog.Debug("evicting metrics reporter from cache")
			go func() {
				if err := v.provider.Shutdown(ctx); err != nil {
					log.Warn("error shutting down metrics provider", "error", err)
				}
			}()
		}, r.newTracers)
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

	r.traceExporter = instrumentTraceExporter(exporter, ctxInfo.Metrics)

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

	r.bsp = trace.NewBatchSpanProcessor(r.traceExporter, opts...)

	return &r, nil
}

func httpTracer(ctx context.Context, cfg *TracesConfig) (*otlptrace.Exporter, error) {
	topts, err := getHTTPTracesEndpointOptions(cfg)
	if err != nil {
		return nil, err
	}
	texp, err := otlptracehttp.New(ctx, topts.AsTraceHTTP()...)
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
	texp, err := otlptracegrpc.New(ctx, topts.AsTraceGRPC()...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC trace exporter: %w", err)
	}
	return texp, nil
}

// instrumentTraceExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed traces exporter inside an instrumented exporter
func instrumentTraceExporter(in trace.SpanExporter, internalMetrics imetrics.Reporter) trace.SpanExporter {
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
	log := tlog()
	log.Debug("closing all the traces reporters")
	for _, key := range r.reporters.pool.Keys() {
		v, _ := r.reporters.pool.Get(key)
		plog := log.With("serviceName", key)
		plog.Debug("shutting down traces provider")
		if err := v.provider.Shutdown(r.ctx); err != nil {
			log.Error("closing traces provider", err)
		}
	}
	if err := r.traceExporter.Shutdown(r.ctx); err != nil {
		log.Error("closing traces exporter", err)
	}
}

// https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/http/#status
func httpSpanStatusCode(span *request.Span) codes.Code {
	if span.Status < 400 {
		return codes.Unset
	}

	if span.Status < 500 {
		if span.Type == request.EventTypeHTTPClient {
			return codes.Error
		}
		return codes.Unset
	}

	return codes.Error
}

// https://opentelemetry.io/docs/specs/otel/trace/semantic_conventions/rpc/#grpc-status
func grpcSpanStatusCode(span *request.Span) codes.Code {
	if span.Type == request.EventTypeGRPCClient {
		if span.Status == int(semconv.RPCGRPCStatusCodeOk.Value.AsInt64()) {
			return codes.Unset
		}
		return codes.Error
	}

	switch int64(span.Status) {
	case semconv.RPCGRPCStatusCodeUnknown.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeDeadlineExceeded.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeUnimplemented.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeInternal.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeUnavailable.Value.AsInt64(),
		semconv.RPCGRPCStatusCodeDataLoss.Value.AsInt64():
		return codes.Error
	}

	return codes.Unset
}

func spanStatusCode(span *request.Span) codes.Code {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeHTTPClient:
		return httpSpanStatusCode(span)
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return grpcSpanStatusCode(span)
	}
	return codes.Unset
}

func (r *TracesReporter) traceAttributes(span *request.Span) []attribute.KeyValue {
	var attrs []attribute.KeyValue

	switch span.Type {
	case request.EventTypeHTTP:
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
	case request.EventTypeGRPC:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			semconv.NetSockPeerAddr(span.Peer),
			semconv.NetHostName(span.Host),
			semconv.NetHostPort(span.HostPort),
		}
	case request.EventTypeHTTPClient:
		attrs = []attribute.KeyValue{
			semconv.HTTPMethod(span.Method),
			semconv.HTTPStatusCode(span.Status),
			semconv.HTTPURL(span.Path),
			semconv.NetPeerName(span.Host),
			semconv.NetPeerPort(span.HostPort),
			semconv.HTTPRequestContentLength(int(span.ContentLength)),
		}
	case request.EventTypeGRPCClient:
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

	// append extra metadata
	for key, val := range span.Metadata {
		attrs = append(attrs, attribute.String(key, val))
	}

	return attrs
}

func traceName(span *request.Span) string {
	switch span.Type {
	case request.EventTypeHTTP:
		name := span.Method
		if span.Route != "" {
			name += " " + span.Route
		}
		return name
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return span.Path
	case request.EventTypeHTTPClient:
		return span.Method
	}
	return ""
}

func spanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient:
		return trace2.SpanKindClient
	}
	return trace2.SpanKindInternal
}

func handleTraceparentField(parentCtx context.Context, traceparent string) context.Context {
	// If traceparent was not set in eBPF, entire field should be zeroed bytes.
	if len(traceparent) < 55 || traceparent[0] == 0 {
		return parentCtx
	}

	// See https://www.w3.org/TR/trace-context/#traceparent-header-field-values for format.
	// 2 hex version + dash + 32 hex traceID + dash + 16 hex parent + dash + 2 hex flags
	traceID := string(traceparent[3:35])

	if traceID != "" {
		tid, err := trace2.TraceIDFromHex(traceID)
		if err != nil {
			slog.Debug("Invalid TraceID", "error:", err, "traceId:", traceID)
		} else {
			spanCtx := trace2.SpanContextFromContext(parentCtx).WithTraceID(tid)
			parentCtx = trace2.ContextWithSpanContext(parentCtx, spanCtx)

			// Otel loads parent-id into SpanID
			parentID := string(traceparent[36:52])
			spanID, err := trace2.SpanIDFromHex(parentID)
			if err != nil {
				slog.Debug("Invalid ParentID", "error:", err, "parentId:", parentID)
			} else {
				spanCtx := trace2.SpanContextFromContext(parentCtx).WithSpanID(spanID)
				parentCtx = trace2.ContextWithSpanContext(parentCtx, spanCtx)
			}

			// Propagate the trace flags
			traceFlags := string(traceparent[53:55])
			flags, err := hex.DecodeString(traceFlags)
			if err != nil {
				slog.Debug("Invalid trace flags", "error:", err, "traceFlags:", traceFlags)
			} else {
				spanCtx = trace2.SpanContextFromContext(parentCtx).WithTraceFlags(trace2.TraceFlags(flags[0]))
				parentCtx = trace2.ContextWithSpanContext(parentCtx, spanCtx)
			}
		}
	}
	return parentCtx
}

func (r *TracesReporter) makeSpan(parentCtx context.Context, tracer trace2.Tracer, span *request.Span) SessionSpan {
	t := span.Timings()

	parentCtx = handleTraceparentField(parentCtx, span.Traceparent)

	// Create a parent span for the whole request session
	ctx, sp := tracer.Start(parentCtx, traceName(span),
		trace2.WithTimestamp(t.RequestStart),
		trace2.WithSpanKind(spanKind(span)),
		trace2.WithAttributes(r.traceAttributes(span)...),
	)

	sp.SetStatus(spanStatusCode(span), "")

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

func (r *TracesReporter) reportClientSpan(span *request.Span, tracer trace2.Tracer) {
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
				cs = []request.Span{*span}
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

func (r *TracesReporter) reportServerSpan(span *request.Span, tracer trace2.Tracer) {

	s := r.makeSpan(r.ctx, tracer, span)
	if span.ID != 0 {
		topSpans.Add(span.ID, s)
		cs, ok := clientSpans.Get(span.ID)
		newer := []request.Span{}
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

func (r *TracesReporter) reportTraces(input <-chan []request.Span) {
	lastSvc := ""
	var reporter trace2.Tracer
	for spans := range input {
		for i := range spans {
			span := &spans[i]

			// small optimization: read explanation in MetricsReporter.reportMetrics
			if span.ServiceName != lastSvc || reporter == nil {
				lm, err := r.reporters.For(span.ServiceName)
				if err != nil {
					mlog().Error("unexpected error creating OTEL resource. Ignoring trace",
						err, "serviceName", span.ServiceName)
					continue
				}
				lastSvc = span.ServiceName
				reporter = lm.tracer
			}

			switch span.Type {
			case request.EventTypeHTTPClient, request.EventTypeGRPCClient:
				r.reportClientSpan(span, reporter)
			case request.EventTypeHTTP, request.EventTypeGRPC:
				r.reportServerSpan(span, reporter)
			}
		}
	}
	r.close()
}

func (r *TracesReporter) newTracers(svcName string) (*Tracers, error) {
	tlog().Debug("creating new Tracers reporter", "serviceName", svcName)
	tracers := Tracers{
		provider: trace.NewTracerProvider(
			trace.WithResource(otelResource(svcName, r.namespace)),
			trace.WithSpanProcessor(r.bsp),
			trace.WithSampler(trace.ParentBased(trace.TraceIDRatioBased(r.cfg.SamplingRatio))),
		),
	}
	tracers.tracer = tracers.provider.Tracer(reporterName)
	return &tracers, nil
}

func parseTracesEndpoint(cfg *TracesConfig) (*url.URL, bool, error) {
	isCommon := false
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		isCommon = true
		endpoint = cfg.CommonEndpoint
	}

	murl, err := url.Parse(endpoint)
	if err != nil {
		return nil, isCommon, fmt.Errorf("parsing endpoint URL %s: %w", endpoint, err)
	}
	if murl.Scheme == "" || murl.Host == "" {
		return nil, isCommon, fmt.Errorf("URL %q must have a scheme and a host", endpoint)
	}
	return murl, isCommon, nil
}

func getHTTPTracesEndpointOptions(cfg *TracesConfig) (otlpOptions, error) {
	opts := otlpOptions{}
	log := tlog().With("transport", "http")

	murl, isCommon, err := parseTracesEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	setTracesProtocol(cfg)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/metrics to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = murl.Path
	if isCommon {
		if strings.HasSuffix(opts.URLPath, "/") {
			opts.URLPath += "v1/traces"
		} else {
			opts.URLPath += "/v1/traces"
		}
		log.Debug("Specifying path", "path", opts.URLPath)
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	return opts, nil
}

func getGRPCTracesEndpointOptions(cfg *TracesConfig) (otlpOptions, error) {
	opts := otlpOptions{}
	log := tlog().With("transport", "grpc")
	murl, _, err := parseTracesEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	return opts, nil
}

// HACK: at the time of writing this, the otelptracehttp API does not support explicitly
// setting the protocol. They should be properly set via environment variables, but
// if the user supplied the value via configuration file (and not via env vars), we override the environment.
// To be as least intrusive as possible, we will change the variables if strictly needed
// TODO: remove this once otelptracehttp.WithProtocol is supported
func setTracesProtocol(cfg *TracesConfig) {
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
		return
	}
	// unset. Guessing it
	os.Setenv(envTracesProtocol, string(cfg.GuessProtocol()))
}
