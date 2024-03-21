package grafanaagent

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"go.uber.org/zap"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
)

// TracesOTELReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func TracesOTELReceiver(ctx context.Context, cfg otel.TracesConfig) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		// Disable queuing to ensure that we execute the request when calling ConsumeMetrics
		// otherwise we will not see any errors.
		config.QueueConfig.Enabled = false
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: cfg.CommonEndpoint,
		}
		// var opts []trace.BatchSpanProcessorOption
		// if cfg.MaxExportBatchSize > 0 {
		// 	opts = append(opts, trace.WithMaxExportBatchSize(cfg.MaxExportBatchSize))
		// }
		// if cfg.MaxQueueSize > 0 {
		// 	opts = append(opts, trace.WithMaxQueueSize(cfg.MaxQueueSize))
		// }
		// if cfg.BatchTimeout > 0 {
		// 	opts = append(opts, trace.WithBatchTimeout(cfg.BatchTimeout))
		// }
		// if cfg.ExportTimeout > 0 {
		// 	opts = append(opts, trace.WithExportTimeout(cfg.ExportTimeout))
		// }
		// tracer, _ := otel.HttpTracer(ctx, &cfg)
		// bsp := trace.NewBatchSpanProcessor(tracer, opts...)
		// provider := trace.NewTracerProvider(
		// 	trace.WithSpanProcessor(bsp),
		// 	trace.WithSampler(cfg.Sampler.Implementation()),
		// 	trace.WithIDGenerator(&otel.BeylaIDGenerator{}),
		// )
		telemetrySettings := component.TelemetrySettings{
			Logger:         zap.NewNop(),
			MeterProvider:  metric.NewMeterProvider(),
			TracerProvider: trace.NewTracerProvider(),
			MetricsLevel:   configtelemetry.LevelBasic,
			ReportStatus: func(event *component.StatusEvent) {
				if err := event.Err(); err != nil {
					slog.Error("error reported by component", "error", err)
				}
			},
		}
		set := exporter.CreateSettings{
			ID:                component.NewIDWithName(component.DataTypeMetrics, "beyla"),
			TelemetrySettings: telemetrySettings,
		}

		exp, err := factory.CreateTracesExporter(ctx, set, config)
		if err != nil {
			slog.Error("error creating traces exporter", "error", err)
			return
		}
		defer func() {
			exp.Shutdown(ctx)
		}()
		exp.Start(ctx, nil)
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreTraces {
					continue
				}
				ctx, traces := generateTraces(ctx, span)
				err := exp.ConsumeTraces(ctx, traces)
				if err != nil {
					slog.Error("error sending trace to consumer", "error", err)
				}
			}
		}
	}, nil
}
