package otel

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"
	"go.uber.org/zap"

	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesReceiver(ctx context.Context, cfg TracesConfig, ctxInfo *global.ContextInfo) pipe.FinalProvider[[]request.Span] {
	return (&tracesOTELReceiver{ctx: ctx, cfg: cfg, ctxInfo: ctxInfo}).provideLoop
}

type tracesOTELReceiver struct {
	ctx     context.Context
	cfg     TracesConfig
	ctxInfo *global.ContextInfo
}

func (tr *tracesOTELReceiver) provideLoop() (pipe.FinalFunc[[]request.Span], error) {
	if !tr.cfg.Enabled() {
		return pipe.IgnoreFinal[[]request.Span](), nil
	}
	return func(in <-chan []request.Span) {
		exp, err := getTracesExporter(tr.ctx, tr.cfg, tr.ctxInfo)
		if err != nil {
			slog.Error("error creating traces exporter", "error", err)
			return
		}
		defer func() {
			exp.Shutdown(tr.ctx)
		}()
		exp.Start(tr.ctx, nil)
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}
				traces := GenerateTraces(span)
				err := exp.ConsumeTraces(tr.ctx, traces)
				if err != nil {
					slog.Error("error sending trace to consumer", "error", err)
				}
			}
		}
	}, nil
}

func getTracesExporter(ctx context.Context, cfg TracesConfig, ctxInfo *global.ContextInfo) (exporter.Traces, error) {
	switch proto := cfg.GetProtocol(); proto {
	case ProtocolHTTPJSON, ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		slog.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var t trace.SpanExporter
		var err error

		if t, err = HttpTracer(ctx, &cfg); err != nil {
			slog.Error("can't instantiate OTEL HTTP traces exporter", err)
			return nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		config.QueueConfig.Enabled = false
		endpoint := cfg.CommonEndpoint
		if endpoint == "" {
			endpoint = cfg.TracesEndpoint
		}
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: endpoint,
		}
		set := getTraceSettings(ctxInfo, cfg, t)
		return factory.CreateTracesExporter(ctx, set, config)
	case ProtocolGRPC:
		var t trace.SpanExporter
		var err error

		slog.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		if t, err = GRPCTracer(ctx, &cfg); err != nil {
			slog.Error("can't instantiate OTEL GRPC traces exporter: %w", err)
			return nil, err
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		config.QueueConfig.Enabled = false
		endpoint := cfg.CommonEndpoint
		if endpoint == "" {
			endpoint = cfg.TracesEndpoint
		}
		config.ClientConfig = configgrpc.ClientConfig{
			Endpoint: endpoint,
			TLSSetting: configtls.ClientConfig{
				Insecure:           true, // TODO: make this configurable
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
		}
		set := getTraceSettings(ctxInfo, cfg, t)
		return factory.CreateTracesExporter(ctx, set, config)
	default:
		slog.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, ProtocolGRPC, ProtocolHTTPJSON, ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}

}

func getTraceSettings(ctxInfo *global.ContextInfo, cfg TracesConfig, in trace.SpanExporter) exporter.CreateSettings {
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
	tracer := InstrumentTraceExporter(in, ctxInfo.Metrics)
	bsp := trace.NewBatchSpanProcessor(tracer, opts...)
	provider := trace.NewTracerProvider(
		trace.WithSpanProcessor(bsp),
		trace.WithSampler(cfg.Sampler.Implementation()),
	)
	telemetrySettings := component.TelemetrySettings{
		Logger:         zap.NewNop(),
		MeterProvider:  metric.NewMeterProvider(),
		TracerProvider: provider,
		MetricsLevel:   configtelemetry.LevelBasic,
		ReportStatus: func(event *component.StatusEvent) {
			if err := event.Err(); err != nil {
				slog.Error("error reported by component", "error", err)
			}
		},
	}
	return exporter.CreateSettings{
		ID:                component.NewIDWithName(component.DataTypeMetrics, "beyla"),
		TelemetrySettings: telemetrySettings,
	}
}

// GenerateTraces creates a ptrace.Traces from a request.Span
func GenerateTraces(span *request.Span) ptrace.Traces {
	t := span.Timings()
	start := SpanStartTime(t)
	hasSubSpans := t.Start.After(start)
	traces := ptrace.NewTraces()
	rs := traces.ResourceSpans().AppendEmpty()
	ss := rs.ScopeSpans().AppendEmpty()
	resourceAttrs := attrsToMap(Resource(span.ServiceID).Attributes())
	resourceAttrs.PutStr(string(semconv.OTelLibraryNameKey), ReporterName)
	resourceAttrs.CopyTo(rs.Resource().Attributes())

	traceID := pcommon.TraceID(span.TraceID)
	spanID := pcommon.SpanID(RandomSpanID())
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
	s.SetName(TraceName(span))
	s.SetKind(ptrace.SpanKind(SpanKind(span)))
	s.SetStartTimestamp(pcommon.NewTimestampFromTime(start))

	// Set trace and span IDs
	s.SetSpanID(spanID)
	s.SetTraceID(traceID)
	if span.ParentSpanID.IsValid() {
		s.SetParentSpanID(pcommon.SpanID(span.ParentSpanID))
	}

	// Set span attributes
	attrs := TraceAttributes(span)
	m := attrsToMap(attrs)
	m.CopyTo(s.Attributes())

	// Set status code
	statusCode := codeToStatusCode(SpanStatusCode(span))
	s.Status().SetCode(statusCode)
	s.SetEndTimestamp(pcommon.NewTimestampFromTime(t.End))
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
	for _, attr := range attrs {
		switch v := attr.Value.AsInterface().(type) {
		case string:
			m.PutStr(string(attr.Key), v)
		case int64:
			m.PutInt(string(attr.Key), v)
		case float64:
			m.PutDouble(string(attr.Key), v)
		case bool:
			m.PutBool(string(attr.Key), v)
		}
	}
	return m
}

// codeToStatusCode converts a codes.Code to a ptrace.StatusCode
func codeToStatusCode(code codes.Code) ptrace.StatusCode {
	switch code {
	case codes.Unset:
		return ptrace.StatusCodeUnset
	case codes.Error:
		return ptrace.StatusCodeError
	case codes.Ok:
		return ptrace.StatusCodeOk
	}
	return ptrace.StatusCodeUnset
}
