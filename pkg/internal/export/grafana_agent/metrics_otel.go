package grafanaagent

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.uber.org/zap"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// MetricsReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry metrics to the configured consumers.
func MetricsOTELReceiver(ctx context.Context, cfg otel.MetricsConfig) (node.TerminalFunc[[]request.Span], error) {
	return func(in <-chan []request.Span) {
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		// Disable queuing to ensure that we execute the request when calling ConsumeMetrics
		// otherwise we will not see any errors.
		config.QueueConfig.Enabled = false
		endpoint := cfg.CommonEndpoint
		if endpoint == "" {
			endpoint = cfg.MetricsEndpoint
		}
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: endpoint,
		}
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

		exp, err := factory.CreateMetricsExporter(ctx, set, config)
		if err != nil {
			slog.Error("error creating metrics exporter", "error", err)
			return
		}
		defer func() {
			err := exp.Shutdown(ctx)
			if err != nil {
				slog.Error("error shutting down metrics exporter", "error", err)
			}
		}()
		err = exp.Start(ctx, nil)
		if err != nil {
			slog.Error("error starting metrics exporter", "error", err)
		}
		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if span.IgnoreSpan == request.IgnoreMetrics {
					continue
				}

				m := generateMetrics(&cfg, span)
				err := exp.ConsumeMetrics(ctx, m)
				if err != nil {
					slog.Error("error sending metrics to consumer", "error", err)
				}
			}
		}
	}, nil
}
