package alloy

import (
	"context"
	"log/slog"
	"time"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
)

func etrlog() *slog.Logger {
	return slog.With("component", "ConnectionSpansReceiver")
}

// ConnectionSpansReceiver creates a terminal node that forwards the received traces as inter-cluster connection
// traces. They only include minimal information about the source and destination services as well as the
// trace ID, so tempo can use them to build service graph metrics that otherwise could not be created by Beyla.
// It also adds the "beyla.span.type" attribute with the value "external" to all traces, so Tempo would later
// remove them.
func ConnectionSpansReceiver(
	ctxInfo *global.ContextInfo,
	cfg *beyla.TracesReceiverConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		tr := &connectionSpansReceiver{
			hostID:           ctxInfo.HostID,
			input:            input.Subscribe(),
			samplerImpl:      cfg.Sampler.Implementation(),
			attributeGetters: otel.ConnectionSpanAttributes(),
			traceConsumers:   cfg.Traces,
			// TODO: share it with the other metrics receivers
			attributeCache: expirable.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
		}
		return tr.provideLoop, nil
	}
}

type connectionSpansReceiver struct {
	samplerImpl      trace.Sampler
	hostID           string
	input            <-chan []request.Span
	traceConsumers   []beyla.Consumer
	attributeCache   *expirable.LRU[svc.UID, []attribute.KeyValue]
	attributeGetters []attributes.Getter[*request.Span, attribute.KeyValue]
}

func (tr *connectionSpansReceiver) provideLoop(ctx context.Context) {
	swarms.ForEachInput(ctx, tr.input, etrlog().Debug, func(spans []request.Span) {
		for _, spanGroup := range tr.groupExternSpans(ctx, spans) {
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
	})
}

func (tr *connectionSpansReceiver) groupExternSpans(ctx context.Context, spans []request.Span) map[svc.UID][]tracesgen.TraceSpanAndAttributes {
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
		for _, getter := range tr.attributeGetters {
			finalAttrs = append(finalAttrs, getter(span))
		}

		sr := sampler.ShouldSample(trace.SamplingParameters{
			ParentContext: ctx,
			Name:          span.TraceName(),
			TraceID:       span.TraceID,
			Kind:          otel.SpanKind(span),
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
