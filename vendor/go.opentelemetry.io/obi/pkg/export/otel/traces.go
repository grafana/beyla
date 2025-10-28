// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.uber.org/zap"

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
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

const reporterName = "go.opentelemetry.io/obi"

func otlog() *slog.Logger {
	return slog.With("component", "otel.TracesReceiver")
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
		input:              input.Subscribe(msg.SubscriberName("otel.TracesReceiver")),
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

func (tr *tracesOTELReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	traceAttrs, err := tracesgen.UserSelectedAttributes(tr.selectorCfg)
	if err != nil {
		return nil, err
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return traceAttrs, nil
}

func (tr *tracesOTELReceiver) processSpans(ctx context.Context, exp exporter.Traces, spans []request.Span, traceAttrs map[attr.Name]struct{}, sampler trace.Sampler) {
	spanGroups := tracesgen.GroupSpans(ctx, spans, traceAttrs, sampler, tr.is)

	for _, spanGroup := range spanGroups {
		if len(spanGroup) > 0 {
			sample := spanGroup[0]

			if !sample.Span.Service.ExportModes.CanExportTraces() {
				continue
			}

			envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
			if tr.spanMetricsEnabled {
				envResourceAttrs = append(envResourceAttrs, attribute.Bool(string(attr.SkipSpanMetrics.OTEL()), true))
			}
			traces := tracesgen.GenerateTracesWithAttributes(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.ctxInfo.HostID, spanGroup, reporterName, tr.ctxInfo.ExtraResourceAttributes...)
			err := exp.ConsumeTraces(ctx, traces)
			if err != nil {
				slog.Error("error sending trace to consumer", "error", err)
			}
		}
	}
}

func (tr *tracesOTELReceiver) provideLoop(ctx context.Context) {
	exp, err := getTracesExporter(ctx, tr.cfg, tr.ctxInfo.Metrics)
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

	sampler := tr.cfg.SamplerConfig.Implementation()
	swarms.ForEachInput(ctx, tr.input, otlog().Debug, func(spans []request.Span) {
		tr.processSpans(ctx, exp, spans, traceAttrs, sampler)
	})
}

// instrumentTracesExporter checks whether the context is configured to report internal metrics and,
// in this case, wraps the passed metrics exporter inside an instrumented exporter
func instrumentTracesExporter(internalMetrics imetrics.Reporter, in exporter.Traces) exporter.Traces {
	// avoid wrapping the instrumented exporter if we don't have
	// internal instrumentation (NoopReporter)
	if _, ok := internalMetrics.(imetrics.NoopReporter); ok || internalMetrics == nil {
		return in
	}
	return &instrumentedTracesExporter{
		Traces:   in,
		internal: internalMetrics,
	}
}

//nolint:cyclop
func getTracesExporter(ctx context.Context, cfg otelcfg.TracesConfig, im imetrics.Reporter) (exporter.Traces, error) {
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
			batchCfg.MinSize = int64(cfg.MaxQueueSize)
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
		exp, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			slog.Error("can't create OTLP HTTP traces exporter", "error", err)
			return nil, err
		}
		exp = instrumentTracesExporter(im, exp)
		// TODO: remove this once the batcher helper is added to otlphttpexporter
		return exporterhelper.NewTraces(ctx, set, cfg,
			exp.ConsumeTraces,
			exporterhelper.WithStart(exp.Start),
			exporterhelper.WithShutdown(exp.Shutdown),
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
			batchCfg.MinSize = int64(cfg.MaxQueueSize)
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
		exp, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			return nil, err
		}
		exp = instrumentTracesExporter(im, exp)
		return exp, nil
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

func convertHeaders(headers map[string]string) map[string]configopaque.String {
	opaqueHeaders := make(map[string]configopaque.String)
	for key, value := range headers {
		opaqueHeaders[key] = configopaque.String(value)
	}
	return opaqueHeaders
}
