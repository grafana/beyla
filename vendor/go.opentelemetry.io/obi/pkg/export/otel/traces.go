// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	trace2 "go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const reporterName = "go.opentelemetry.io/obi"

type TraceSpanAndAttributes struct {
	Span       *request.Span
	Attributes []attribute.KeyValue
}

type SpanAttr struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

func makeTracesReceiver(
	cfg otelcfg.TracesConfig,
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
	cfg otelcfg.TracesConfig,
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
	cfg                otelcfg.TracesConfig
	ctxInfo            *global.ContextInfo
	selectorCfg        *attributes.SelectorConfig
	is                 instrumentations.InstrumentationSelection
	spanMetricsEnabled bool
	attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
	input              <-chan []request.Span
}

func userSelectedAttributes(selectorCfg *attributes.SelectorConfig) (map[attr.Name]struct{}, error) {
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
	traceAttrs, err := userSelectedAttributes(tr.selectorCfg)
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

func groupSpans(ctx context.Context, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler, is instrumentations.InstrumentationSelection) map[svc.UID][]TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]TraceSpanAndAttributes{}

	for i := range spans {
		span := &spans[i]
		if span.InternalSignal() {
			continue
		}
		if spanDiscarded(span, is) {
			continue
		}

		finalAttrs := traceAttributes(span, traceAttrs)

		spanSampler := func() trace.Sampler {
			if span.Service.Sampler != nil {
				return span.Service.Sampler
			}

			return sampler
		}

		sr := spanSampler().ShouldSample(trace.SamplingParameters{
			ParentContext: ctx,
			Name:          span.TraceName(),
			TraceID:       span.TraceID,
			Kind:          spanKind(span),
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
	spanGroups := groupSpans(ctx, spans, traceAttrs, sampler, tr.is)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]

			if !sample.Span.Service.ExportModes.CanExportTraces() {
				continue
			}

			envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
			traces := generateTracesWithAttributes(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.ctxInfo.HostID, spanGroup, tr.ctxInfo.ExtraResourceAttributes...)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				slog.Error("error sending trace to consumer", "error", err)
			}
		}
	}
}

func (tr *tracesOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getTracesExporter(ctx, tr.cfg)
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

	sampler := tr.cfg.SamplerConfig.Implementation()

	for spans := range tr.input {
		tr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	}
}

//nolint:cyclop
func getTracesExporter(ctx context.Context, cfg otelcfg.TracesConfig) (exporter.Traces, error) {
	switch proto := cfg.GetProtocol(); proto {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		slog.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var err error

		opts, err := otelcfg.HTTPTracesEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get HTTP traces endpoint options", "error", err)
			return nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		queueConfig := exporterhelper.NewDefaultQueueConfig()
		queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
		batchCfg := exporterhelper.BatchConfig{
			Sizer: queueConfig.Sizer,
		}
		if cfg.MaxQueueSize > 0 || cfg.BatchTimeout > 0 {
			queueConfig.Enabled = true
		}
		if cfg.MaxQueueSize > 0 {
			batchCfg.MaxSize = int64(cfg.MaxQueueSize)
		}
		if cfg.BatchTimeout > 0 {
			batchCfg.FlushTimeout = cfg.BatchTimeout
		}
		queueConfig.Batch = configoptional.Some(batchCfg)
		config.QueueConfig = queueConfig
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
		set := getTraceSettings(factory.Type())
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
			exporterhelper.WithRetry(config.RetryConfig))
	case otelcfg.ProtocolGRPC:
		slog.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		var err error
		opts, err := otelcfg.GRPCTracesEndpointOptions(&cfg)
		if err != nil {
			slog.Error("can't get GRPC traces endpoint options", "error", err)
			return nil, err
		}
		endpoint, _, err := otelcfg.ParseTracesEndpoint(&cfg)
		if err != nil {
			slog.Error("can't parse GRPC traces endpoint", "error", err)
			return nil, err
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		queueConfig := exporterhelper.NewDefaultQueueConfig()
		queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
		batchCfg := exporterhelper.BatchConfig{
			Sizer: queueConfig.Sizer,
		}
		if cfg.MaxQueueSize > 0 || cfg.BatchTimeout > 0 {
			queueConfig.Enabled = true
		}
		if cfg.MaxQueueSize > 0 {
			batchCfg.MaxSize = int64(cfg.MaxQueueSize)
		}
		if cfg.BatchTimeout > 0 {
			batchCfg.FlushTimeout = cfg.BatchTimeout
		}
		queueConfig.Batch = configoptional.Some(batchCfg)
		config.QueueConfig = queueConfig
		config.RetryConfig = getRetrySettings(cfg)
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: endpoint.String(),
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		set := getTraceSettings(factory.Type())
		return factory.CreateTraces(ctx, set, config)
	default:
		slog.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, otelcfg.ProtocolGRPC, otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}
}

func getTraceSettings(dataTypeMetrics component.Type) exporter.Settings {
	traceProvider := tracenoop.NewTracerProvider()
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

func getRetrySettings(cfg otelcfg.TracesConfig) configretry.BackOffConfig {
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

var emptyUID = svc.UID{}

func traceAppResourceAttrs(cache *expirable2.LRU[svc.UID, []attribute.KeyValue], hostID string, service *svc.Attrs) []attribute.KeyValue {
	// TODO: remove?
	if service.UID == emptyUID {
		return otelcfg.GetAppResourceAttrs(hostID, service)
	}

	attrs, ok := cache.Get(service.UID)
	if ok {
		return attrs
	}
	attrs = otelcfg.GetAppResourceAttrs(hostID, service)
	cache.Add(service.UID, attrs)

	return attrs
}

func generateTracesWithAttributes(
	cache *expirable2.LRU[svc.UID, []attribute.KeyValue],
	svc *svc.Attrs,
	envResourceAttrs []attribute.KeyValue,
	hostID string,
	spans []TraceSpanAndAttributes,
	extraResAttrs ...attribute.KeyValue,
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
		s.SetKind(ptrace.SpanKind(spanKind(span)))
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
	case request.EventTypeMongoClient:
		return is.MongoEnabled()
	case request.EventTypeManualSpan:
		return true
	}

	return false
}

// TODO use semconv.DBSystemRedis when we update to OTEL semantic conventions library 1.30
var (
	dbSystemRedis   = attribute.String(string(attr.DBSystemName), semconv.DBSystemRedis.Value.AsString())
	dbSystemMongo   = attribute.String(string(attr.DBSystemName), semconv.DBSystemMongoDB.Value.AsString())
	spanMetricsSkip = attribute.Bool(string(attr.SkipSpanMetrics), true)
)

//nolint:cyclop
func traceAttributes(span *request.Span, optionalAttrs map[attr.Name]struct{}) []attribute.KeyValue {
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
		if span.Status == 1 {
			attrs = append(attrs, request.DBResponseStatusCode(strconv.Itoa(int(span.SQLError.Code))))
			attrs = append(attrs, request.ErrorType(span.SQLError.SQLState))
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
	case request.EventTypeMongoClient:
		attrs = []attribute.KeyValue{
			request.ServerAddr(request.HostAsServer(span)),
			request.ServerPort(span.HostPort),
			dbSystemMongo,
		}
		operation := span.Method
		if operation != "" {
			attrs = append(attrs, request.DBOperationName(operation))
		}
		if span.Path != "" {
			attrs = append(attrs, request.DBCollectionName(span.Path))
		}
		if span.Status == 1 {
			attrs = append(attrs, request.DBResponseStatusCode(span.DBError.ErrorCode))
		}
		if span.DBNamespace != "" {
			attrs = append(attrs, request.DBNamespace(span.DBNamespace))
		}
	case request.EventTypeManualSpan:
		attrs = manualSpanAttributes(span)
	}

	if _, ok := optionalAttrs[attr.SkipSpanMetrics]; ok {
		attrs = append(attrs, spanMetricsSkip)
	}

	return attrs
}

func spanKind(span *request.Span) trace2.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer, request.EventTypeKafkaServer:
		return trace2.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient, request.EventTypeRedisClient, request.EventTypeMongoClient:
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

func manualSpanAttributes(span *request.Span) []attribute.KeyValue {
	attrs := []attribute.KeyValue{}

	if span.Statement == "" {
		return attrs
	}

	var unmarshaledAttrs []SpanAttr
	err := json.Unmarshal([]byte(span.Statement), &unmarshaledAttrs)
	if err != nil {
		fmt.Println(err)
		return attrs
	}

	for i := range unmarshaledAttrs {
		akv := unmarshaledAttrs[i]
		key := unix.ByteSliceToString(akv.Key[:])
		switch akv.Vtype {
		case uint8(attribute.BOOL):
			attrs = append(attrs, attribute.Bool(key, akv.Value[0] != 0))
		case uint8(attribute.INT64):
			v := binary.LittleEndian.Uint64(akv.Value[:8])
			attrs = append(attrs, attribute.Int(key, int(v)))
		case uint8(attribute.FLOAT64):
			v := math.Float64frombits(binary.LittleEndian.Uint64(akv.Value[:8]))
			attrs = append(attrs, attribute.Float64(key, v))
		case uint8(attribute.STRING):
			attrs = append(attrs, attribute.String(key, unix.ByteSliceToString(akv.Value[:])))
		}
	}

	return attrs
}
