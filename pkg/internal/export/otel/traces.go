package otel

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

func tlog() *slog.Logger {
	return slog.With("component", "otel.TracesReporter")
}

const reporterName = "github.com/grafana/beyla"

type TracesConfig struct {
	CommonEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	Protocol       Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	TracesProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"BEYLA_OTEL_INSECURE_SKIP_VERIFY"`

	Sampler Sampler `yaml:"sampler"`

	// Configuration options below this line will remain undocumented at the moment,
	// but can be useful for performance-tuning of some customers.
	MaxExportBatchSize int           `yaml:"max_export_batch_size" env:"BEYLA_OTLP_TRACES_MAX_EXPORT_BATCH_SIZE"`
	MaxQueueSize       int           `yaml:"max_queue_size" env:"BEYLA_OTLP_TRACES_MAX_QUEUE_SIZE"`
	BatchTimeout       time.Duration `yaml:"batch_timeout" env:"BEYLA_OTLP_TRACES_BATCH_TIMEOUT"`
	ExportTimeout      time.Duration `yaml:"export_timeout" env:"BEYLA_OTLP_TRACES_EXPORT_TIMEOUT"`

	ReportersCacheLen int `yaml:"reporters_cache_len" env:"BEYLA_TRACES_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"BEYLA_OTEL_SDK_LOG_LEVEL"`

	// Grafana configuration needs to be explicitly set up before building the graph
	Grafana *GrafanaOTLP `yaml:"-"`
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m TracesConfig) Enabled() bool { //nolint:gocritic
	return m.CommonEndpoint != "" || m.TracesEndpoint != "" || m.Grafana.TracesEnabled()
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
	reporters     ReporterPool[*Tracers]
}

// Tracers handles the OTEL traces providers and exporters.
// There is a Tracers instance for each instrumented service/process.
type Tracers struct {
	ctx      context.Context
	provider *trace.TracerProvider
	tracer   trace2.Tracer
}

func ReportTraces(ctx context.Context, cfg *TracesConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]request.Span], error) {

	SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

	tr, err := newTracesReporter(ctx, cfg, ctxInfo)
	if err != nil {
		slog.Error("can't instantiate OTEL traces reporter", err)
		os.Exit(-1)
	}
	return tr.reportTraces, nil
}

func newTracesReporter(ctx context.Context, cfg *TracesConfig, ctxInfo *global.ContextInfo) (*TracesReporter, error) {
	log := tlog()
	r := TracesReporter{ctx: ctx, cfg: cfg}
	r.reporters = NewReporterPool[*Tracers](cfg.ReportersCacheLen,
		func(k svc.UID, v *Tracers) {
			llog := log.With("service", k)
			llog.Debug("evicting traces reporter from cache")
			go func() {
				if err := v.provider.ForceFlush(v.ctx); err != nil {
					llog.Warn("error flushing evicted traces provider", "error", err)
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
		log.Error("closing traces exporter", "error", err)
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

func SpanStatusCode(span *request.Span) codes.Code {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeHTTPClient:
		return httpSpanStatusCode(span)
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return grpcSpanStatusCode(span)
	case request.EventTypeSQLClient:
		if span.Status != 0 {
			return codes.Error
		}
		return codes.Unset
	}
	return codes.Unset
}

func SpanKindString(span *request.Span) string {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC:
		return "SPAN_KIND_SERVER"
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient:
		return "SPAN_KIND_CLIENT"
	}
	return "SPAN_KIND_INTERNAL"
}

func spanHost(span *request.Span) string {
	if span.HostName != "" {
		return span.HostName
	}

	return span.Host
}

func spanPeer(span *request.Span) string {
	if span.PeerName != "" {
		return span.PeerName
	}

	return span.Peer
}

func TraceAttributes(span *request.Span) []attribute.KeyValue {
	var attrs []attribute.KeyValue

	switch span.Type {
	case request.EventTypeHTTP:
		attrs = []attribute.KeyValue{
			HTTPRequestMethod(span.Method),
			HTTPResponseStatusCode(span.Status),
			HTTPUrlPath(span.Path),
			ClientAddr(spanPeer(span)),
			ServerAddr(spanHost(span)),
			ServerPort(span.HostPort),
			HTTPRequestBodySize(int(span.ContentLength)),
		}
		if span.Route != "" {
			attrs = append(attrs, semconv.HTTPRoute(span.Route))
		}
	case request.EventTypeGRPC:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			ClientAddr(spanPeer(span)),
			ServerAddr(spanHost(span)),
			ServerPort(span.HostPort),
		}
	case request.EventTypeHTTPClient:
		attrs = []attribute.KeyValue{
			HTTPRequestMethod(span.Method),
			HTTPResponseStatusCode(span.Status),
			HTTPUrlFull(span.Path),
			ServerAddr(spanHost(span)),
			ServerPort(span.HostPort),
			HTTPRequestBodySize(int(span.ContentLength)),
		}
	case request.EventTypeGRPCClient:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			ServerAddr(spanHost(span)),
			ServerPort(span.HostPort),
		}
	case request.EventTypeSQLClient:
		operation := span.Method
		if operation != "" {
			attrs = []attribute.KeyValue{
				semconv.DBOperation(operation),
			}
			table := span.Path
			if table != "" {
				attrs = append(attrs, semconv.DBSQLTable(table))
			}
		}
	}

	return attrs
}

func TraceName(span *request.Span) string {
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
	case request.EventTypeSQLClient:
		// We don't have db.name, but follow "<db.operation> <db.name>.<db.sql.table_name>"
		// or just "<db.operation>" if table is not known, otherwise just a fixed string.
		operation := span.Method
		if operation == "" {
			return "SQL"
		}
		table := span.Path
		if table != "" {
			operation += " ." + table
		}
		return operation
	}
	return ""
}

func SpanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient:
		return trace2.SpanKindClient
	}
	return trace2.SpanKindInternal
}

func HandleTraceparent(parentCtx context.Context, span *request.Span) context.Context {
	if span.ParentSpanID.IsValid() {
		parentCtx = trace2.ContextWithSpanContext(parentCtx, trace2.SpanContext{}.WithTraceID(span.TraceID).WithSpanID(span.ParentSpanID).WithTraceFlags(trace2.TraceFlags(span.Flags)))
	} else if span.TraceID.IsValid() {
		parentCtx = ContextWithTrace(parentCtx, span.TraceID)
	}

	return parentCtx
}

func SpanStartTime(t request.Timings) time.Time {
	realStart := t.RequestStart
	if t.Start.Before(realStart) {
		realStart = t.Start
	}
	return realStart
}

func (r *TracesReporter) makeSpan(parentCtx context.Context, tracer trace2.Tracer, span *request.Span) {
	t := span.Timings()

	parentCtx = HandleTraceparent(parentCtx, span)
	realStart := SpanStartTime(t)
	hasSubspans := t.Start.After(realStart)

	if !hasSubspans {
		// We set the eBPF calculated trace_id and span_id to be the main span
		parentCtx = ContextWithTraceParent(parentCtx, span.TraceID, span.SpanID)
	}

	// Create a parent span for the whole request session
	ctx, sp := tracer.Start(parentCtx, TraceName(span),
		trace2.WithTimestamp(realStart),
		trace2.WithSpanKind(SpanKind(span)),
		trace2.WithAttributes(TraceAttributes(span)...),
	)

	sp.SetStatus(SpanStatusCode(span), "")

	if hasSubspans {
		var spP trace2.Span

		// Create a child span showing the queue time
		_, spQ := tracer.Start(ctx, "in queue",
			trace2.WithTimestamp(t.RequestStart),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spQ.End(trace2.WithTimestamp(t.Start))

		// Create a child span showing the processing time
		// Override the active context for the span to be the processing span
		// The trace_id and span_id from eBPF are attached here
		ctx = ContextWithTraceParent(ctx, span.TraceID, span.SpanID)
		_, spP = tracer.Start(ctx, "processing",
			trace2.WithTimestamp(t.Start),
			trace2.WithSpanKind(trace2.SpanKindInternal),
		)
		spP.End(trace2.WithTimestamp(t.End))
	}

	sp.End(trace2.WithTimestamp(t.End))
}

func (r *TracesReporter) reportTraces(input <-chan []request.Span) {
	var lastSvcUID svc.UID
	var reporter trace2.Tracer
	for spans := range input {
		for i := range spans {
			span := &spans[i]

			// If we are ignoring this span because of route patterns, don't do anything
			if span.IgnoreSpan == request.IgnoreTraces {
				continue
			}

			// small optimization: read explanation in MetricsReporter.reportMetrics
			if span.ServiceID.UID != lastSvcUID || reporter == nil {
				lm, err := r.reporters.For(span.ServiceID)
				if err != nil {
					tlog().Error("unexpected error creating OTEL resource. Ignoring trace",
						err, "service", span.ServiceID)
					continue
				}
				lastSvcUID = span.ServiceID.UID
				reporter = lm.tracer
			}

			r.makeSpan(r.ctx, reporter, span)
		}
	}
	r.close()
}

func (r *TracesReporter) newTracers(service svc.ID) (*Tracers, error) {
	tlog().Debug("creating new Tracers reporter", "service", service)
	tracers := Tracers{
		ctx: r.ctx,
		provider: trace.NewTracerProvider(
			trace.WithResource(Resource(service)),
			trace.WithSpanProcessor(r.bsp),
			trace.WithSampler(r.cfg.Sampler.Implementation()),
			trace.WithIDGenerator(&BeylaIDGenerator{}),
		),
	}
	tracers.tracer = tracers.provider.Tracer(reporterName)
	return &tracers, nil
}

// the HTTP path will be defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
func parseTracesEndpoint(cfg *TracesConfig) (*url.URL, bool, error) {
	isCommon := false
	endpoint := cfg.TracesEndpoint
	if endpoint == "" {
		isCommon = true
		endpoint = cfg.CommonEndpoint
		if endpoint == "" && cfg.Grafana != nil && cfg.Grafana.CloudZone != "" {
			endpoint = cfg.Grafana.Endpoint()
		}
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

	cfg.Grafana.setupOptions(&opts)

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
