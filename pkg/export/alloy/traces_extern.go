package alloy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/svc"
	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
)

func etrlog() *slog.Logger {
	return slog.With("component", "ExternalTracesReceiver")
}

var BeylaExternSpan = attribute.KeyValue{Key: "beyla.span.type", Value: attribute.StringValue("external")}

// ExternalTracesReceiver creates a terminal node that forwards the received traces as inter-cluster connection
// traces. They only include minimal information about the source and destination services as well as the
// trace ID, so tempo can use them to build service graph metrics that otherwise could not be created by Beyla.
// It also adds the "beyla.span.type" attribute with the value "external" to all traces, so Tempo would later
// remove them.
func ExternalTracesReceiver(
	ctxInfo *global.ContextInfo,
	cfg *beyla.TracesReceiverConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		tr := &externalTracesReceiver{
			hostID: ctxInfo.HostID,
			input:          input.Subscribe(),
			attributeValueGetters: valueGetters(),
			samplerImpl: cfg.Sampler.Implementation(),
			traceConsumers: cfg.Traces,
			// TODO: share it with the other metrics receivers
			attributeCache: expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),

		}
		return tr.provideLoop, nil
	}
}

type externalTracesReceiver struct {
	samplerImpl           trace.Sampler
	hostID                string
	input                 <-chan []request.Span
	attributeValueGetters []attributes.Getter[*request.Span, attribute.KeyValue]
	traceConsumers        []beyla.Consumer
	attributeCache        *expirable2.LRU[svc.UID, []attribute.KeyValue]
}

func (tr *externalTracesReceiver) provideLoop(ctx context.Context) {

	for {
		select {
		case <-ctx.Done():
			return
		case spans, ok := <-tr.input:
			if !ok {
				return
			}
			spanGroups := tr.groupExternSpans(ctx, spans)
			for _, spanGroup := range spanGroups {
				if len(spanGroup) > 0 {
					sample := spanGroup[0]
					if !sample.Span.Service.ExportModes.CanExportTraces() {
						continue
					}

					envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
					for _, tc := range tr.traceConsumers {
						traces := tracesgen.GenerateTracesWithAttributes(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.hostID, spanGroup, otel.ReporterName)
						err := tc.ConsumeTraces(ctx, traces)
						if err != nil {
							slog.Error("error sending trace to consumer", "error", err)
						}
					}
				}
			}
		}
	}
}

func valueGetters() []attributes.Getter[*request.Span, attribute.KeyValue] {
	attributeValueGetters := make([]attributes.Getter[*request.Span, attribute.KeyValue], 0, 5)
	for _, name := range []attr.Name{attr.Client, attr.Server, attr.ClientAddr, attr.ServerAddr} {
		getter, ok := request.SpanOTELGetters(name)
		if !ok {
			panic(fmt.Sprintf("attribute %s not found in SpanOTELGetters", name))
		}
		attributeValueGetters = append(attributeValueGetters, getter)
	}
	return append(attributeValueGetters, func(*request.Span) attribute.KeyValue {
		return BeylaExternSpan
	})
}

func (tr *externalTracesReceiver) groupExternSpans(ctx context.Context, spans []request.Span) map[svc.UID][]tracesgen.TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]tracesgen.TraceSpanAndAttributes{}

	for i := range spans {
		span := &spans[i]
		if span.InternalSignal() {
			continue
		}

		// a span can override the sampler
		sampler := tr.samplerImpl
		if span.Service.Sampler != nil {
			sampler = span.Service.Sampler
		}

		// get the values for the span attributes
		finalAttrs := make([]attribute.KeyValue, 0, 5)
		for _, getter := range tr.attributeValueGetters {
			finalAttrs = append(finalAttrs, getter(span))
		}

		sr := sampler.ShouldSample(trace.SamplingParameters{
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
			group = []tracesgen.TraceSpanAndAttributes{}
		}
		group = append(group, tracesgen.TraceSpanAndAttributes{Span: span, Attributes: finalAttrs})
		spanGroups[span.Service.UID] = group
	}

	return spanGroups
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

func getTracesExporter() {
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
}