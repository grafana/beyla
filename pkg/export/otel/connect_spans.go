package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

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
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// TODO: integrate with Beyla internal metrics

var beylaSpan = attribute.KeyValue{Key: "beyla.topology", Value: attribute.StringValue("external")}

// ConnectionSpanAttributes do not use any user-defined set of attributes but a reduced set of attributes
// that will be exclusively used from Tempo to create inter-cluster service graph metrics
func ConnectionSpanAttributes(unresolvedNames request.UnresolvedNames) []attributes.Getter[*request.Span, attribute.KeyValue] {
	functionalGetters := request.SpanOTELGetters(unresolvedNames)
	attributeValueGetters := make([]attributes.Getter[*request.Span, attribute.KeyValue], 0, 5)
	for _, name := range []attr.Name{attr.Client, attr.Server, attr.ClientAddr, attr.ServerAddr} {
		getter, ok := functionalGetters(name)
		if !ok {
			// BUG! Check switch inside SpanOTELGetters
			panic(fmt.Sprintf("attribute %s not found in SpanOTELGetters", name))
		}
		attributeValueGetters = append(attributeValueGetters, getter)
	}
	return append(attributeValueGetters, func(*request.Span) attribute.KeyValue {
		return beylaSpan
	})
}

// ConnectionSpansExport creates a terminal node that consumes inter-cluster spans and sends them to the configured
// exporter. Inter-cluster spans are smaller than regular spans and marked for removal by Tempo
func ConnectionSpansExport(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.TracesConfig,
	unresolvedNames request.UnresolvedNames,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}
		tr := makeConnectionSpansExport(cfg, unresolvedNames, ctxInfo, input)
		return tr.provideLoop, nil
	}
}

func makeConnectionSpansExport(
	cfg *otelcfg.TracesConfig,
	unresolvedNames request.UnresolvedNames,
	ctxInfo *global.ContextInfo,
	input *msg.Queue[[]request.Span],
) *connectionSpansExport {
	return &connectionSpansExport{
		log:               slog.With("component", "otel.ConnectionSpansExport"),
		cfg:               cfg,
		ctxInfo:           ctxInfo,
		attributeProvider: ConnectionSpanAttributes(unresolvedNames),
		is:                instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
		input:             input.Subscribe(msg.SubscriberName("otel.ConnectionSpansExport")),
	}
}

type connectionSpansExport struct {
	log               *slog.Logger
	cfg               *otelcfg.TracesConfig
	ctxInfo           *global.ContextInfo
	is                instrumentations.InstrumentationSelection
	input             <-chan []request.Span
	attributeProvider []attributes.Getter[*request.Span, attribute.KeyValue]
}

func (tr *connectionSpansExport) processSpans(ctx context.Context, exp exporter.Traces, spans []request.Span) {
	spanGroups := GroupConnectionSpans(spans, tr.is, tr.attributeProvider)
	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := &spanGroup[0]

			if !sample.Span.Service.ExportModes.CanExportTraces() {
				continue
			}

			// append external attribute
			sample.Attributes = make([]attribute.KeyValue, 0, len(tr.attributeProvider))
			for _, getter := range tr.attributeProvider {
				sample.Attributes = append(sample.Attributes, getter(sample.Span))
			}

			// set attributes for src and dst
			traces := GenerateConnectSpans(tr.ctxInfo.HostID, sample.Span, spanGroup)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				tr.log.Error("error sending trace to consumer", "error", err)
			}
		}
	}
}

func (tr *connectionSpansExport) provideLoop(ctx context.Context) {
	exp, err := tr.getTracesExporter(ctx)
	if err != nil {
		tr.log.Error("error creating traces exporter", "error", err)
		return
	}
	defer func() {
		err := exp.Shutdown(ctx)
		if err != nil {
			tr.log.Error("error shutting down traces exporter", "error", err)
		}
	}()
	err = exp.Start(ctx, nil)
	if err != nil {
		tr.log.Error("error starting traces exporter", "error", err)
		return
	}

	swarms.ForEachInput(ctx, tr.input, tr.log.Debug, func(spans []request.Span) {
		tr.processSpans(ctx, exp, spans)
	})
}

//nolint:cyclop
func (tr *connectionSpansExport) getTracesExporter(ctx context.Context) (exporter.Traces, error) {
	switch proto := tr.cfg.GetProtocol(); proto {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		tr.log.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var err error

		opts, err := otelcfg.HTTPTracesEndpointOptions(tr.cfg)
		if err != nil {
			tr.log.Error("can't get HTTP traces endpoint options", "error", err)
			return nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		queueConfig := exporterhelper.NewDefaultQueueConfig()
		queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
		batchCfg := exporterhelper.BatchConfig{
			Sizer: queueConfig.Sizer,
		}
		if tr.cfg.MaxQueueSize > 0 || tr.cfg.BatchTimeout > 0 {
			queueConfig.Enabled = true
		}
		if tr.cfg.MaxQueueSize > 0 {
			batchCfg.MaxSize = int64(tr.cfg.MaxQueueSize)
		}
		if tr.cfg.BatchTimeout > 0 {
			batchCfg.FlushTimeout = tr.cfg.BatchTimeout
		}
		queueConfig.Batch = configoptional.Some(batchCfg)
		config.QueueConfig = queueConfig
		config.RetryConfig = getRetrySettings(tr.cfg)
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: tr.cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		tr.log.Debug("getTracesExporter: confighttp.ClientConfig created", "endpoint", config.ClientConfig.Endpoint)
		set := getTraceSettings(factory.Type())
		exp, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			tr.log.Error("can't create OTLP HTTP traces exporter", "error", err)
			return nil, err
		}
		// TODO: remove this once the batcher helper is added to otlphttpexporter
		return exporterhelper.NewTraces(ctx, set, tr.cfg,
			exp.ConsumeTraces,
			exporterhelper.WithStart(exp.Start),
			exporterhelper.WithShutdown(exp.Shutdown),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
			exporterhelper.WithQueue(config.QueueConfig),
			exporterhelper.WithRetry(config.RetryConfig))
	case otelcfg.ProtocolGRPC:
		tr.log.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		var err error
		opts, err := otelcfg.GRPCTracesEndpointOptions(tr.cfg)
		if err != nil {
			tr.log.Error("can't get GRPC traces endpoint options", "error", err)
			return nil, err
		}
		endpoint, _, err := otelcfg.ParseTracesEndpoint(tr.cfg)
		if err != nil {
			tr.log.Error("can't parse GRPC traces endpoint", "error", err)
			return nil, err
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		queueConfig := exporterhelper.NewDefaultQueueConfig()
		queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
		batchCfg := exporterhelper.BatchConfig{
			Sizer: queueConfig.Sizer,
		}
		if tr.cfg.MaxQueueSize > 0 || tr.cfg.BatchTimeout > 0 {
			queueConfig.Enabled = true
		}
		if tr.cfg.MaxQueueSize > 0 {
			batchCfg.MaxSize = int64(tr.cfg.MaxQueueSize)
		}
		if tr.cfg.BatchTimeout > 0 {
			batchCfg.FlushTimeout = tr.cfg.BatchTimeout
		}
		queueConfig.Batch = configoptional.Some(batchCfg)
		config.QueueConfig = queueConfig
		config.RetryConfig = getRetrySettings(tr.cfg)
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: endpoint.String(),
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: tr.cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		set := getTraceSettings(factory.Type())
		exp, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			return nil, err
		}
		return exp, nil
	default:
		tr.log.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, otelcfg.ProtocolGRPC, otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}
}

func getTraceSettings(dataTypeMetrics component.Type) exporter.Settings {
	traceProvider := noop.NewTracerProvider()
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

func getRetrySettings(cfg *otelcfg.TracesConfig) configretry.BackOffConfig {
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

func convertHeaders(headers map[string]string) configopaque.MapList {
	opaqueHeaders := make(configopaque.MapList, 0, len(headers))
	for key, value := range headers {
		opaqueHeaders = append(opaqueHeaders, configopaque.Pair{Name: key, Value: configopaque.String(value)})
	}
	return opaqueHeaders
}

func GroupConnectionSpans(
	spans []request.Span,
	selector instrumentations.InstrumentationSelection,
	attributeProvider []attributes.Getter[*request.Span, attribute.KeyValue],
) map[svc.UID][]tracesgen.TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]tracesgen.TraceSpanAndAttributes{}

	for i := range spans {
		span := &spans[i]
		if span.InternalSignal() {
			continue
		}
		if tracesgen.SpanDiscarded(span, selector) {
			continue
		}

		finalAttrs := make([]attribute.KeyValue, 0, len(attributeProvider))
		for _, getter := range attributeProvider {
			finalAttrs = append(finalAttrs, getter(span))
		}

		group := spanGroups[span.Service.UID]
		group = append(group, tracesgen.TraceSpanAndAttributes{Span: span, Attributes: finalAttrs})
		spanGroups[span.Service.UID] = group
	}

	return spanGroups
}

func GenerateConnectSpans(
	hostID string,
	span *request.Span,
	spans []tracesgen.TraceSpanAndAttributes,
) ptrace.Traces {
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	// set trace Resource attributes
	// TODO: check if we can remove some of them
	resourceAttrs := otelcfg.GetAppResourceAttrs(hostID, &span.Service)
	resourceAttrs = append(resourceAttrs, otelcfg.ResourceAttrsFromEnv(&span.Service)...)
	// Override OBI library name by Beyla
	resourceAttrsMap := tracesgen.AttrsToMap(resourceAttrs)
	resourceAttrsMap.PutStr(string(semconv.OTelLibraryNameKey), ReporterName)
	resourceAttrsMap.MoveTo(rs.Resource().Attributes())

	for _, spanWithAttributes := range spans {
		span := spanWithAttributes.Span
		attrs := spanWithAttributes.Attributes

		ss := rs.ScopeSpans().AppendEmpty()

		timing := span.Timings()
		start := spanStartTime(timing)

		traceID := pcommon.TraceID(span.TraceID)
		spanID := pcommon.SpanID(idgen.RandomSpanID())
		// This should never happen
		if traceID.IsEmpty() {
			traceID = pcommon.TraceID(idgen.RandomTraceID())
		}

		if span.SpanID.IsValid() {
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
		m := tracesgen.AttrsToMap(attrs)
		m.MoveTo(s.Attributes())

		// Set status code
		statusCode := tracesgen.CodeToStatusCode(request.SpanStatusCode(span))
		s.Status().SetCode(statusCode)
		statusMessage := request.SpanStatusMessage(span)
		if statusMessage != "" {
			s.Status().SetMessage(statusMessage)
		}
		s.SetEndTimestamp(pcommon.NewTimestampFromTime(timing.End))
	}
	return traces
}

func spanStartTime(t request.Timings) time.Time {
	realStart := t.RequestStart
	if t.Start.Before(realStart) {
		realStart = t.Start
	}
	return realStart
}
