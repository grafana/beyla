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
	"go.opentelemetry.io/otel/sdk/metric"
	trace2 "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/zap"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

var timeNow = time.Now

const (
	SurveyInfoMetricName = "survey_info"
	ReporterName         = "github.com/grafana/beyla"
)

// ResolveOTLPEndpoint returns the OTLP endpoint, defined from one of the following sources, from highest to lowest priority
// - OTEL_EXPORTER_OTLP_METRICS_ENDPOINT, if defined
// - OTEL_EXPORTER_OTLP_ENDPOINT, if defined
// - https://otlp-gateway-${GRAFANA_CLOUD_ZONE}.grafana.net/otlp, if GRAFANA_CLOUD_ZONE is defined
// If, by some reason, Grafana changes its OTLP Gateway URL in a distant future, you can still point to the
// correct URL with the OTLP_EXPORTER_... variables.
// Returns true if the endpoint is common for both traces and metrics.
func ResolveOTLPEndpoint(endpoint, common string, grafana *GrafanaOTLP) (string, bool) {
	if endpoint != "" {
		return endpoint, false
	}

	if common != "" {
		return common, true
	}

	if grafana != nil && grafana.CloudZone != "" && grafana.Endpoint() != "" {
		return grafana.Endpoint(), true
	}

	return "", false
}

func SpanKind(span *request.Span) trace2.SpanKind {
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

func getQueueConfig(cfg *otelcfg.TracesConfig) configoptional.Optional[exporterhelper.QueueBatchConfig] {
	// enable batching only if the queue config is enabled
	if cfg.BatchMaxSize <= 0 && cfg.BatchTimeout <= 0 && cfg.QueueSize <= 0 {
		return configoptional.None[exporterhelper.QueueBatchConfig]()
	}

	queueConfig := exporterhelper.NewDefaultQueueConfig()
	queueConfig.Sizer = exporterhelper.RequestSizerTypeItems
	// Avoid continuously seeing "sending queue is full" errors in the standard output
	queueConfig.BlockOnOverflow = true
	if cfg.QueueSize > 0 {
		queueConfig.QueueSize = int64(cfg.QueueSize)
	}
	batchCfg := exporterhelper.BatchConfig{
		Sizer: queueConfig.Sizer,
	}
	batchSet := false
	if cfg.BatchMaxSize > 0 {
		batchSet = true
		batchCfg.MaxSize = int64(cfg.BatchMaxSize)
	}
	if cfg.BatchTimeout > 0 {
		batchSet = true
		batchCfg.FlushTimeout = cfg.BatchTimeout
		batchCfg.MinSize = int64(cfg.BatchMaxSize)
	}
	if batchSet {
		queueConfig.Batch = configoptional.Some(batchCfg)
	}
	return configoptional.Some(queueConfig)
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

//nolint:cyclop
func createTracesExporter(ctx context.Context, cfg *otelcfg.TracesConfig, log *slog.Logger) (exporter.Traces, error) {
	switch proto := cfg.GetProtocol(); proto {
	case otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf, "": // zero value defaults to HTTP for backwards-compatibility
		log.Debug("instantiating HTTP TracesReporter", "protocol", proto)
		var err error

		opts, err := otelcfg.HTTPTracesEndpointOptions(cfg)
		if err != nil {
			log.Error("can't get HTTP traces endpoint options", "error", err)
			return nil, err
		}
		factory := otlphttpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlphttpexporter.Config)
		config.QueueConfig = getQueueConfig(cfg)
		config.RetryConfig = getRetrySettings(cfg)
		config.ClientConfig = confighttp.ClientConfig{
			Endpoint: opts.Scheme + "://" + opts.Endpoint + opts.BaseURLPath,
			TLS: configtls.ClientConfig{
				Insecure:           opts.Insecure,
				InsecureSkipVerify: cfg.InsecureSkipVerify,
			},
			Headers: convertHeaders(opts.Headers),
		}
		log.Debug("createTracesExporter: confighttp.ClientConfig created", "endpoint", config.ClientConfig.Endpoint)
		set := getTraceSettings(factory.Type())
		exp, err := factory.CreateTraces(ctx, set, config)
		if err != nil {
			log.Error("can't create OTLP HTTP traces exporter", "error", err)
			return nil, err
		}
		// TODO: remove this once the batcher helper is added to otlphttpexporter
		return exporterhelper.NewTraces(ctx, set, cfg,
			exp.ConsumeTraces,
			exporterhelper.WithStart(exp.Start),
			exporterhelper.WithShutdown(exp.Shutdown),
			exporterhelper.WithCapabilities(consumer.Capabilities{MutatesData: false}),
			exporterhelper.WithQueue(config.QueueConfig),
			exporterhelper.WithRetry(config.RetryConfig))
	case otelcfg.ProtocolGRPC:
		log.Debug("instantiating GRPC TracesReporter", "protocol", proto)
		var err error
		opts, err := otelcfg.GRPCTracesEndpointOptions(cfg)
		if err != nil {
			log.Error("can't get GRPC traces endpoint options", "error", err)
			return nil, err
		}
		endpoint, _, err := otelcfg.ParseTracesEndpoint(cfg)
		if err != nil {
			log.Error("can't parse GRPC traces endpoint", "error", err)
			return nil, err
		}
		factory := otlpexporter.NewFactory()
		config := factory.CreateDefaultConfig().(*otlpexporter.Config)
		config.QueueConfig = getQueueConfig(cfg)
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
		return exp, nil
	default:
		log.Error(fmt.Sprintf("invalid protocol value: %q. Accepted values are: %s, %s, %s",
			proto, otelcfg.ProtocolGRPC, otelcfg.ProtocolHTTPJSON, otelcfg.ProtocolHTTPProtobuf))
		return nil, fmt.Errorf("invalid protocol value: %q", proto)
	}
}
