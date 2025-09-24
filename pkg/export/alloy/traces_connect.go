package alloy

import (
	"context"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/components/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/trace"
)

func etrlog() *slog.Logger {
	return slog.With("component", "alloy.ConnectionSpansReceiver")
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
			selector:         instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
		}
		return tr.provideLoop, nil
	}
}

type connectionSpansReceiver struct {
	samplerImpl      trace.Sampler
	hostID           string
	input            <-chan []request.Span
	traceConsumers   []beyla.Consumer
	attributeGetters []attributes.Getter[*request.Span, attribute.KeyValue]
	selector         instrumentations.InstrumentationSelection
}

func (tr *connectionSpansReceiver) provideLoop(ctx context.Context) {
	swarms.ForEachInput(ctx, tr.input, etrlog().Debug, func(spans []request.Span) {
		for _, spanGroup := range tr.groupExternSpans(ctx, spans) {
			if len(spanGroup) > 0 {
				sample := spanGroup[0]
				if !sample.Span.Service.ExportModes.CanExportTraces() {
					continue
				}

				for _, tc := range tr.traceConsumers {
					traces := otel.GenerateConnectSpans(tr.hostID, sample.Span, spanGroup)
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
	return otel.GroupConnectionSpans(ctx, spans, tr.samplerImpl, tr.selector, tr.attributeGetters)
}
