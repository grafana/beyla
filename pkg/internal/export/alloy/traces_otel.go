package alloy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesOTELReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesOTELReceiver(ctx context.Context, cfg otel.TracesConfig, ctxInfo *global.ContextInfo) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		exp, err := getTracesExporter(ctx, cfg, ctxInfo)
		if err != nil {
			slog.Error("error creating traces exporter", "error", err)
			return
		}
		defer func() {
			exp.Shutdown(ctx)
			// provider.Shutdown(ctx)
			// tracer.Shutdown(ctx)
		}()
		exp.Start(ctx, nil)
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}
				traces := generateTraces(span)
				err := exp.ConsumeTraces(ctx, traces)
				if err != nil {
					slog.Error("error sending trace to consumer", "error", err)
				}
			}
		}
	}, nil
}

func getTracesExporter(ctx context.Context, cfg otel.TracesConfig, ctxInfo *global.ContextInfo) (exporter.Traces, error) {
	switch proto := cfg.GetProtocol(); proto {
	case otel.ProtocolHTTPJSON, otel.ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		slog.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var t trace.SpanExporter
		var err error

		if t, err = otel.HttpTracer(ctx, &cfg); err != nil {
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
	case otel.ProtocolGRPC:
		var t trace.SpanExporter
		var err error

		slog.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		if t, err = otel.GRPCTracer(ctx, &cfg); err != nil {
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
		}
		set := getTraceSettings(ctxInfo, cfg, t)
		return factory.CreateTracesExporter(ctx, set, config)
	default:
		slog.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, otel.ProtocolGRPC, otel.ProtocolHTTPJSON, otel.ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}

}

func getTraceSettings(ctxInfo *global.ContextInfo, cfg otel.TracesConfig, in trace.SpanExporter) exporter.CreateSettings {
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
	tracer := otel.InstrumentTraceExporter(in, ctxInfo.Metrics)
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
