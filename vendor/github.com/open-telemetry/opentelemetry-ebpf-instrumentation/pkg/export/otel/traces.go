// TODO: remove this after batching API becomes stable
//
//nolint:staticcheck
package otel

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"strings"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	trace2 "go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/imetrics"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/instrumentations"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

func tlog() *slog.Logger {
	return slog.With("component", "otel.TracesReporter")
}

const reporterName = "github.com/open-telemetry/opentelemetry-ebpf-instrumentation"

type TraceSpanAndAttributes struct {
	Span       *request.Span
	Attributes []attribute.KeyValue
}

type TracesConfig struct {
	CommonEndpoint string `yaml:"-" env:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	TracesEndpoint string `yaml:"endpoint" env:"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"`

	Protocol       Protocol `yaml:"protocol" env:"OTEL_EXPORTER_OTLP_PROTOCOL"`
	TracesProtocol Protocol `yaml:"-" env:"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"`

	// Allows configuration of which instrumentations should be enabled, e.g. http, grpc, sql...
	Instrumentations []string `yaml:"instrumentations" env:"OTEL_EBPF_OTEL_TRACES_INSTRUMENTATIONS" envSeparator:","`

	// InsecureSkipVerify is not standard, so we don't follow the same naming convention
	InsecureSkipVerify bool `yaml:"insecure_skip_verify" env:"OTEL_EBPF_OTEL_INSECURE_SKIP_VERIFY"`

	Sampler Sampler `yaml:"sampler"`

	// Configuration options below this line will remain undocumented at the moment,
	// but can be useful for performance-tuning of some customers.
	//nolint:undoc
	MaxExportBatchSize int `yaml:"max_export_batch_size" env:"OTEL_EBPF_OTLP_TRACES_MAX_EXPORT_BATCH_SIZE"`
	//nolint:undoc
	MaxQueueSize int `yaml:"max_queue_size" env:"OTEL_EBPF_OTLP_TRACES_MAX_QUEUE_SIZE"`
	//nolint:undoc
	BatchTimeout time.Duration `yaml:"batch_timeout" env:"OTEL_EBPF_OTLP_TRACES_BATCH_TIMEOUT"`

	// Configuration options for BackOffConfig of the traces exporter.
	// See https://github.com/open-telemetry/opentelemetry-collector/blob/main/config/configretry/backoff.go
	// BackOffInitialInterval the time to wait after the first failure before retrying.
	//nolint:undoc
	BackOffInitialInterval time.Duration `yaml:"backoff_initial_interval" env:"OTEL_EBPF_BACKOFF_INITIAL_INTERVAL"`
	// BackOffMaxInterval is the upper bound on backoff interval.
	//nolint:undoc
	BackOffMaxInterval time.Duration `yaml:"backoff_max_interval" env:"OTEL_EBPF_BACKOFF_MAX_INTERVAL"`
	// BackOffMaxElapsedTime is the maximum amount of time (including retries) spent trying to send a request/batch.
	//nolint:undoc
	BackOffMaxElapsedTime time.Duration `yaml:"backoff_max_elapsed_time" env:"OTEL_EBPF_BACKOFF_MAX_ELAPSED_TIME"`
	//nolint:undoc
	ReportersCacheLen int `yaml:"reporters_cache_len" env:"OTEL_EBPF_TRACES_REPORT_CACHE_LEN"`

	// SDKLogLevel works independently from the global LogLevel because it prints GBs of logs in Debug mode
	// and the Info messages leak internal details that are not usually valuable for the final user.
	//nolint:undoc
	SDKLogLevel string `yaml:"otel_sdk_log_level" env:"OTEL_EBPF_OTEL_SDK_LOG_LEVEL"`

	// OTLPEndpointProvider allows overriding the OTLP Endpoint. It needs to return an endpoint and
	// a boolean indicating if the endpoint is common for both traces and metrics
	OTLPEndpointProvider func() (string, bool) `yaml:"-" env:"-"`

	// InjectHeaders allows injecting custom headers to the HTTP OTLP exporter
	InjectHeaders func(dst map[string]string) `yaml:"-" env:"-"`
}

// Enabled specifies that the OTEL traces node is enabled if and only if
// either the OTEL endpoint and OTEL traces endpoint is defined.
// If not enabled, this node won't be instantiated
func (m *TracesConfig) Enabled() bool {
	return m.CommonEndpoint != "" || m.TracesEndpoint != ""
}

func (m *TracesConfig) GetProtocol() Protocol {
	if m.TracesProtocol != "" {
		return m.TracesProtocol
	}
	if m.Protocol != "" {
		return m.Protocol
	}
	return m.guessProtocol()
}

func (m *TracesConfig) OTLPTracesEndpoint() (string, bool) {
	if m.OTLPEndpointProvider != nil {
		return m.OTLPEndpointProvider()
	}
	return ResolveOTLPEndpoint(m.TracesEndpoint, m.CommonEndpoint)
}

func (m *TracesConfig) guessProtocol() Protocol {
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

func makeTracesReceiver(
	cfg TracesConfig,
	spanMetricsEnabled bool,
	ctxInfo *global.ContextInfo,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) *tracesOTELReceiver {
	return &tracesOTELReceiver{
		cfg:                cfg,
		ctxInfo:            ctxInfo,
		selectorCfg:        selectorCfg,
		is:                 instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
		spanMetricsEnabled: spanMetricsEnabled,
		input:              input.Subscribe(),
		attributeCache:     expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
	}
}

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesReceiver(
	ctxInfo *global.ContextInfo,
	cfg TracesConfig,
	spanMetricsEnabled bool,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		tr := makeTracesReceiver(cfg, spanMetricsEnabled, ctxInfo, selectorCfg, input)
		return tr.provideLoop, nil
	}
}

type tracesOTELReceiver struct {
	cfg                TracesConfig
	ctxInfo            *global.ContextInfo
	selectorCfg        *attributes.SelectorConfig
	is                 instrumentations.InstrumentationSelection
	spanMetricsEnabled bool
	attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
	input              <-chan []request.Span
}

func GetUserSelectedAttributes(selectorCfg *attributes.SelectorConfig) (map[attr.Name]struct{}, error) {
	// Get user attributes
	attribProvider, err := attributes.NewAttrSelector(attributes.GroupTraces, selectorCfg)
	if err != nil {
		return nil, err
	}
	traceAttrsArr := attribProvider.For(attributes.Traces)
	traceAttrs := make(map[attr.Name]struct{})
	for _, a := range traceAttrsArr {
		traceAttrs[a] = struct{}{}
	}

	return traceAttrs, err
}

func (tr *tracesOTELReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	traceAttrs, err := GetUserSelectedAttributes(tr.selectorCfg)
	if err != nil {
		return nil, err
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return traceAttrs, nil
}

func spanDiscarded(span *request.Span, is instrumentations.InstrumentationSelection) bool {
	return request.IgnoreTraces(span) || span.Service.ExportsOTelTraces() || !acceptSpan(is, span)
}

func GroupSpans(ctx context.Context, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler, is instrumentations.InstrumentationSelection) map[svc.UID][]TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]TraceSpanAndAttributes{}

	for i := range spans {
		span := &spans[i]
		if span.InternalSignal() {
			continue
		}
		if spanDiscarded(span, is) {
			continue
		}

		finalAttrs := TraceAttributes(span, traceAttrs)

		sr := sampler.ShouldSample(trace.SamplingParameters{
			ParentContext: ctx,
			Name:          span.TraceName(),
			TraceID:       span.TraceID,
			Kind:          SpanKind(span),
			Attributes:    finalAttrs,
		})

		if sr.Decision == trace.Drop {
			continue
		}

		group, ok := spanGroups[span.Service.UID]
		if !ok {
			group = []TraceSpanAndAttributes{}
		}
		group = append(group, TraceSpanAndAttributes{Span: span, Attributes: finalAttrs})
		spanGroups[span.Service.UID] = group
	}

	return spanGroups
}

func (tr *tracesOTELReceiver) processSpans(ctx context.Context, exp exporter.Traces, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler) {
	spanGroups := GroupSpans(ctx, spans, traceAttrs, sampler, tr.is)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]
			envResourceAttrs := ResourceAttrsFromEnv(&sample.Span.Service)
			traces := generateTracesWithAttributes(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.ctxInfo.HostID, spanGroup, tr.ctxInfo.ExtraResourceAttributes)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				slog.Error("error sending trace to consumer", "error", err)
			}
		}
	}
}

func (tr *tracesOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getTracesExporter(ctx, tr.cfg, tr.ctxInfo)
	if err != nil {
		slog.Error("error creating traces exporter", "error", err)
		return
	}
	defer func() {
		err := exp.Shutdown(ctx)
		if err != nil {
			slog.Error("error shutting down traces exporter", "error", err)
		}
	}()
	err = exp.Start(ctx, nil)
	if err != nil {
		slog.Error("error starting traces exporter", "error", err)
		return
	}

	traceAttrs, err := tr.getConstantAttributes()
	if err != nil {
		slog.Error("error selecting user trace attributes", "error", err)
		return
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}

	sampler := tr.cfg.Sampler.Implementation()

	for spans := range tr.input {
		tr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	}
}

//nolint:cyclop
func getTracesExporter(ctx context.Context, cfg TracesConfig, ctxInfo *global.ContextInfo) (exporter.Traces, error) {
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		slog.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var t trace.SpanExporter
		var err error

		opts, err := getHTTPTracesEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get HTTP traces endpoint options", "error", err)
			return nil, err
		}
		if t, err = httpTracer(ctx, opts); err != nil {
			slog.Error("can't instantiate OTEL HTTP traces exporter", "error", err)
			return nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		// Experimental API for batching
		// See: https://github.com/open-telemetry/opentelemetry-collector/issues/8122
		batchCfg := exporterhelper.NewDefaultBatcherConfig()
		if cfg.MaxQueueSize > 0 {
			batchCfg.SizeConfig.MaxSize = int64(cfg.MaxExportBatchSize)
		}
		if cfg.BatchTimeout > 0 {
			batchCfg.FlushTimeout = cfg.BatchTimeout
		}
		config.RetryConfig = getRetrySettings(cfg)
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		slog.Debug("getTracesExporter: confighttp.ClientConfig created", "endpoint", config.ClientConfig.Endpoint)
		set := getTraceSettings(ctxInfo, factory.Type(), t, &batchCfg)
		exporter, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			slog.Error("can't create OTLP HTTP traces exporter", "error", err)
			return nil, err
		}
		// TODO: remove this once the batcher helper is added to otlphttpexporter
		return exporterhelper.NewTraces(ctx, set, cfg,
			exporter.ConsumeTraces,
			exporterhelper.WithStart(exporter.Start),
			exporterhelper.WithShutdown(exporter.Shutdown),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
			exporterhelper.WithQueue(config.QueueConfig),
			exporterhelper.WithBatcher(batchCfg),
			exporterhelper.WithRetry(config.RetryConfig))
	case ProtocolGRPC:
		slog.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		var t trace.SpanExporter
		var err error
		opts, err := getGRPCTracesEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get GRPC traces endpoint options", "error", err)
			return nil, err
		}
		if t, err = grpcTracer(ctx, opts); err != nil {
			slog.Error("can't instantiate OTEL GRPC traces exporter", "error", err)
			return nil, err
		}
		endpoint, _, err := parseTracesEndpoint(&cfg)
		if err != nil {
			slog.Error("can't parse GRPC traces endpoint", "error", err)
			return nil, err
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		// Experimental API for batching
		// See: https://github.com/open-telemetry/opentelemetry-collector/issues/8122
		if cfg.MaxExportBatchSize > 0 {
			config.BatcherConfig.Enabled = true
			config.BatcherConfig.SizeConfig.MaxSize = int64(cfg.MaxExportBatchSize)
		}
		if cfg.BatchTimeout > 0 {
			config.BatcherConfig.FlushTimeout = cfg.BatchTimeout
		}
		config.RetryConfig = getRetrySettings(cfg)
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: endpoint.String(),
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		set := getTraceSettings(ctxInfo, factory.Type(), t, &config.BatcherConfig)
		return factory.CreateTraces(ctx, set, config)
	default:
		slog.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}
}

func internalMetricsEnabled(ctxInfo *global.ContextInfo) bool {
	internalMetrics := ctxInfo.Metrics
	if internalMetrics == nil {
		return false
	}
	_, ok := internalMetrics.(imetrics.NoopReporter)

	return !ok
}

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

func getTraceSettings(
	ctxInfo *global.ContextInfo,
	dataTypeMetrics component.Type,
	in trace.SpanExporter,
	batcherCfg *exporterhelper.BatcherConfig,
) exporter.Settings {
	var traceProvider trace2.TracerProvider
	traceProvider = tracenoop.NewTracerProvider()
	if internalMetricsEnabled(ctxInfo) {
		spanExporter := instrumentTraceExporter(in, ctxInfo.Metrics)
		res := newResourceInternal(ctxInfo.HostID)
		traceProvider = trace.NewTracerProvider(
			trace.WithBatcher(spanExporter, getInternalBatchSpanOpts(batcherCfg)...),
			trace.WithResource(res),
		)
	}
	meterProvider := metric.NewMeterProvider()
	telemetrySettings := component.TelemetrySettings{
		Logger:         zap.NewNop(),
		MeterProvider:  meterProvider,
		TracerProvider: traceProvider,
		Resource:       pcommon.NewResource(),
	}

	return exporter.Settings{
		ID:                component.NewIDWithName(dataTypeMetrics, "beyla"),
		TelemetrySettings: telemetrySettings,
	}
}

func getInternalBatchSpanOpts(cfg *exporterhelper.BatcherConfig) []trace.BatchSpanProcessorOption {
	var opts []trace.BatchSpanProcessorOption
	if cfg.FlushTimeout > 0 {
		opts = append(opts, trace.WithBatchTimeout(cfg.FlushTimeout))
	}
	if cfg.MaxSize > 0 {
		opts = append(opts, trace.WithMaxQueueSize(int(cfg.MaxSize)))
	}
	return opts
}

func getRetrySettings(cfg TracesConfig) configretry.BackOffConfig {
	backOffCfg := configretry.NewDefaultBackOffConfig()
	if cfg.BackOffInitialInterval > 0 {
		backOffCfg.InitialInterval = cfg.BackOffInitialInterval
	}
	if cfg.BackOffMaxInterval > 0 {
		backOffCfg.MaxInterval = cfg.BackOffMaxInterval
	}
	if cfg.BackOffMaxElapsedTime > 0 {
		backOffCfg.MaxElapsedTime = cfg.BackOffMaxElapsedTime
	}
	return backOffCfg
}

func traceAppResourceAttrs(cache *expirable2.LRU[svc.UID, []attribute.KeyValue], hostID string, service *svc.Attrs) []attribute.KeyValue {
	// TODO: remove?
	if service.UID == emptyUID {
		return GetAppResourceAttrs(hostID, service)
	}

	attrs, ok := cache.Get(service.UID)
	if ok {
		return attrs
	}
	attrs = GetAppResourceAttrs(hostID, service)
	cache.Add(service.UID, attrs)

	return attrs
}

func generateTracesWithAttributes(
	cache *expirable2.LRU[svc.UID, []attribute.KeyValue],
	svc *svc.Attrs,
	envResourceAttrs []attribute.KeyValue,
	hostID string,
	spans []TraceSpanAndAttributes,
	extraResAttrs []attribute.KeyValue,
) ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	resourceAttrs := traceAppResourceAttrs(cache, hostID, svc)
	resourceAttrs = append(resourceAttrs, envResourceAttrs...)
	resourceAttrsMap := attrsToMap(resourceAttrs)
	resourceAttrsMap.PutStr(string(semconv.OTelLibraryNameKey), reporterName)
	addAttrsToMap(extraResAttrs, resourceAttrsMap)
	resourceAttrsMap.MoveTo(rs.Resource().Attributes())

	for _, spanWithAttributes := range spans {
		span := spanWithAttributes.Span
		attrs := spanWithAttributes.Attributes

		ss := rs.ScopeSpans().AppendEmpty()

		t := span.Timings()
		start := spanStartTime(t)
		hasSubSpans := t.Start.After(start)

		traceID := pcommon.TraceID(span.TraceID)
		spanID := pcommon.SpanID(RandomSpanID())
		// This should never happen
		if traceID.IsEmpty() {
			traceID = pcommon.TraceID(RandomTraceID())
		}

		if hasSubSpans {
			createSubSpans(span, spanID, traceID, &ss, t)
		} else if span.SpanID.IsValid() {
			spanID = pcommon.SpanID(span.SpanID)
		}

		// Create a parent span for the whole request session
		s := ss.Spans().AppendEmpty()
		s.SetName(span.TraceName())
		s.SetKind(ptrace.SpanKind(SpanKind(span)))
		s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

		// Set trace and span IDs
		s.SetSpanID(spanID)
		s.SetTraceID(traceID)
		if span.ParentSpanID.IsValid() {
			s.SetParentSpanID(pcommon.SpanID(span.ParentSpanID))
		}

		// Set span attributes
		m := attrsToMap(attrs)
		m.MoveTo(s.Attributes())

		// Set status code
		statusCode := codeToStatusCode(request.SpanStatusCode(span))
		s.Status().SetCode(statusCode)
		statusMessage := request.SpanStatusMessage(span)
		if statusMessage != "" {
			s.Status().SetMessage(statusMessage)
		}
		s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	}
	return traces
}

// GenerateTraces creates a ptrace.Traces from a request.Span
func GenerateTraces(
	cache *expirable2.LRU[svc.UID, []attribute.KeyValue],
	svc *svc.Attrs,
	envResourceAttrs []attribute.KeyValue,
	hostID string,
	spans []TraceSpanAndAttributes,
	extraResAttrs ...attribute.KeyValue,
) ptrace.Traces {
	return generateTracesWithAttributes(cache, svc, envResourceAttrs, hostID, spans, extraResAttrs)
}

// createSubSpans creates the internal spans for a request.Span
func createSubSpans(span *request.Span, parentSpanID pcommon.SpanID, traceID pcommon.TraceID, ss *ptrace.ScopeSpans, t request.Timings) {
	// Create a child span showing the queue time
	spQ := ss.Spans().AppendEmpty()
	spQ.SetName("in queue")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(t.RequestStart))
	spQ.SetKind(ptrace.SpanKindInternal)
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spQ.SetTraceID(traceID)
	spQ.SetSpanID(pcommon.SpanID(RandomSpanID()))
	spQ.SetParentSpanID(parentSpanID)

	// Create a child span showing the processing time
	spP := ss.Spans().AppendEmpty()
	spP.SetName("processing")
	spP.SetStartTimestamp(pcommon.NewTimestampFromTime(t.Start))
	spP.SetKind(ptrace.SpanKindInternal)
	spP.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
	spP.SetTraceID(traceID)
	if span.SpanID.IsValid() {
		spP.SetSpanID(pcommon.SpanID(span.SpanID))
	} else {
		spP.SetSpanID(pcommon.SpanID(RandomSpanID()))
	}
	spP.SetParentSpanID(parentSpanID)
}

// attrsToMap converts a slice of attribute.KeyValue to a pcommon.Map
func attrsToMap(attrs []attribute.KeyValue) pcommon.Map {
	m := pcommon.NewMap()
	addAttrsToMap(attrs, m)
	return m
}

func addAttrsToMap(attrs []attribute.KeyValue, dst pcommon.Map) {
	dst.EnsureCapacity(dst.Len() + len(attrs))
	for _, attr := range attrs {
		switch v := attr.Value.AsInterface().(type) {
		case string:
			dst.PutStr(string(attr.Key), v)
		case int64:
			dst.PutInt(string(attr.Key), v)
		case float64:
			dst.PutDouble(string(attr.Key), v)
		case bool:
			dst.PutBool(string(attr.Key), v)
		}
	}
}

// codeToStatusCode converts a codes.Code to a ptrace.StatusCode
func codeToStatusCode(code string) ptrace.StatusCode {
	switch code {
	case request.StatusCodeUnset:
		return ptrace.StatusCodeUnset
	case request.StatusCodeError:
		return ptrace.StatusCodeError
	case request.StatusCodeOk:
		return ptrace.StatusCodeOk
	}
	return ptrace.StatusCodeUnset
}

func convertHeaders(headers map[string]string) map[string]configopaque.String {
	opaqueHeaders := make(map[string]configopaque.String)
	for key, value := range headers {
		opaqueHeaders[key] = configopaque.String(value)
	}
	return opaqueHeaders
}

func httpTracer(ctx context.Context, opts otlpOptions) (*otlptrace.Exporter, error) {
	texp, err := otlptracehttp.New(ctx, opts.AsTraceHTTP()...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP trace exporter: %w", err)
	}
	return texp, nil
}

func grpcTracer(ctx context.Context, opts otlpOptions) (*otlptrace.Exporter, error) {
	texp, err := otlptracegrpc.New(ctx, opts.AsTraceGRPC()...)
	if err != nil {
		return nil, fmt.Errorf("creating GRPC trace exporter: %w", err)
	}
	return texp, nil
}

func acceptSpan(is instrumentations.InstrumentationSelection, span *request.Span) bool {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeHTTPClient:
		return is.HTTPEnabled()
	case request.EventTypeGRPC, request.EventTypeGRPCClient:
		return is.GRPCEnabled()
	case request.EventTypeSQLClient:
		return is.SQLEnabled()
	case request.EventTypeRedisClient, request.EventTypeRedisServer:
		return is.RedisEnabled()
	case request.EventTypeKafkaClient, request.EventTypeKafkaServer:
		return is.KafkaEnabled()
	}

	return false
}

// TODO use semconv.DBSystemRedis when we update to OTEL semantic conventions library 1.30
var (
	dbSystemRedis   = attribute.String(string(attr.DBSystemName), semconv.DBSystemRedis.Value.AsString())
	spanMetricsSkip = attribute.Bool(string(attr.SkipSpanMetrics), true)
)

//nolint:cyclop
func TraceAttributes(span *request.Span, optionalAttrs map[attr.Name]struct{}) []attribute.KeyValue {
	var attrs []attribute.KeyValue

	switch span.Type {
	case request.EventTypeHTTP:
		attrs = []attribute.KeyValue{
			request.HTTPRequestMethod(span.Method),
			request.HTTPResponseStatusCode(span.Status),
			request.HTTPUrlPath(span.Path),
			request.ClientAddr(request.PeerAsClient(span)),
			request.ServerAddr(request.SpanHost(span)),
			request.ServerPort(span.HostPort),
			request.HTTPRequestBodySize(int(span.RequestBodyLength())),
			request.HTTPResponseBodySize(span.ResponseBodyLength()),
		}
		if span.Route != "" {
			attrs = append(attrs, semconv.HTTPRoute(span.Route))
		}
	case request.EventTypeGRPC:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			request.ClientAddr(request.PeerAsClient(span)),
			request.ServerAddr(request.SpanHost(span)),
			request.ServerPort(span.HostPort),
		}
	case request.EventTypeHTTPClient:
		host := request.HTTPClientHost(span)
		scheme := request.HTTPScheme(span)
		url := span.Path
		if span.HasOriginalHost() {
			url = request.URLFull(scheme, host, span.Path)
		}

		attrs = []attribute.KeyValue{
			request.HTTPRequestMethod(span.Method),
			request.HTTPResponseStatusCode(span.Status),
			request.HTTPUrlFull(url),
			semconv.HTTPScheme(scheme),
			request.ServerAddr(host),
			request.ServerPort(span.HostPort),
			request.HTTPRequestBodySize(int(span.RequestBodyLength())),
			request.HTTPResponseBodySize(span.ResponseBodyLength()),
		}
	case request.EventTypeGRPCClient:
		attrs = []attribute.KeyValue{
			semconv.RPCMethod(span.Path),
			semconv.RPCSystemGRPC,
			semconv.RPCGRPCStatusCodeKey.Int(span.Status),
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
		}
	case request.EventTypeSQLClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			span.DBSystemName(), // We can distinguish in the future for MySQL, Postgres etc
		}
		if _, ok := optionalAttrs[attr.DBQueryText]; ok {
			attrs = append(attrs, request.DBQueryText(span.Statement))
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
			table := span.Path
			if table != "" {
				attrs = append(attrs, request.DBCollectionName(table))
			}
		}
	case request.EventTypeRedisServer, request.EventTypeRedisClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			dbSystemRedis,
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
			if _, ok := optionalAttrs[attr.DBQueryText]; ok {
				query := span.Path
				if query != "" {
					attrs = append(attrs, request.DBQueryText(query))
				}
			}
		}
		if span.Status == 1 {
			attrs = append(attrs, request.DBResponseStatusCode(span.DBError.ErrorCode))
		}
		if span.DBNamespace != "" {
			attrs = append(attrs, request.DBNamespace(span.DBNamespace))
		}
	case request.EventTypeKafkaServer, request.EventTypeKafkaClient:
		operation := request.MessagingOperationType(span.Method)
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			semconv.MessagingSystemKafka,
			semconv.MessagingDestinationName(span.Path),
			semconv.MessagingClientID(span.Statement),
			operation,
		}
	}

	if _, ok := optionalAttrs[attr.SkipSpanMetrics]; ok {
		attrs = append(attrs, spanMetricsSkip)
	}

	return attrs
}

func SpanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer, request.EventTypeKafkaServer:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient, request.EventTypeRedisClient:
		return trace2.SpanKindClient
	case request.EventTypeKafkaClient:
		switch span.Method {
		case request.MessagingPublish:
			return trace2.SpanKindProducer
		case request.MessagingProcess:
			return trace2.SpanKindConsumer
		}
	}
	return trace2.SpanKindInternal
}

func spanStartTime(t request.Timings) time.Time {
	realStart := t.RequestStart
	if t.Start.Before(realStart) {
		realStart = t.Start
	}
	return realStart
}

// the HTTP path will be defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_TRACES_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
func parseTracesEndpoint(cfg *TracesConfig) (*url.URL, bool, error) {
	endpoint, isCommon := cfg.OTLPTracesEndpoint()

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
	opts := otlpOptions{Headers: map[string]string{}}
	log := tlog().With("transport", "http")

	murl, isCommon, err := parseTracesEndpoint(cfg)
	if err != nil {
		return opts, err
	}

	log.Debug("Configuring exporter", "protocol",
		cfg.Protocol, "tracesProtocol", cfg.TracesProtocol, "endpoint", murl.Host)
	setTracesProtocol(cfg)
	opts.Scheme = murl.Scheme
	opts.Endpoint = murl.Host
	if murl.Scheme == "http" || murl.Scheme == "unix" {
		log.Debug("Specifying insecure connection", "scheme", murl.Scheme)
		opts.Insecure = true
	}
	// If the value is set from the OTEL_EXPORTER_OTLP_ENDPOINT common property, we need to add /v1/traces to the path
	// otherwise, we leave the path that is explicitly set by the user
	opts.URLPath = strings.TrimSuffix(murl.Path, "/")
	opts.BaseURLPath = strings.TrimSuffix(opts.URLPath, "/v1/traces")
	if isCommon {
		opts.URLPath += "/v1/traces"
		log.Debug("Specifying path", "path", opts.URLPath)
	}

	if cfg.InsecureSkipVerify {
		log.Debug("Setting InsecureSkipVerify")
		opts.SkipTLSVerify = true
	}

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envTracesHeaders))

	return opts, nil
}

func getGRPCTracesEndpointOptions(cfg *TracesConfig) (otlpOptions, error) {
	opts := otlpOptions{Headers: map[string]string{}}
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

	if cfg.InjectHeaders != nil {
		cfg.InjectHeaders(opts.Headers)
	}
	maps.Copy(opts.Headers, HeadersFromEnv(envHeaders))
	maps.Copy(opts.Headers, HeadersFromEnv(envTracesHeaders))
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
	os.Setenv(envTracesProtocol, string(cfg.guessProtocol()))
}
