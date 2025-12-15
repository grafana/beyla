package alloy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attributes "go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(
	ctxInfo *global.ContextInfo,
	cfg *beyla.TracesReceiverConfig,
	spanMetricsEnabled bool,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		tr := &tracesReceiver{
			cfg: cfg, hostID: ctxInfo.HostID, spanMetricsEnabled: spanMetricsEnabled,
			input:          input.Subscribe(msg.SubscriberName("alloyTracesInput")),
			is:             instrumentations.NewInstrumentationSelection(cfg.Instrumentations),
			attributeCache: expirable2.NewLRU[svc.UID, []attribute.KeyValue](1024, nil, 5*time.Minute),
		}
		// Get user attributes
		if err := tr.fetchConstantAttributes(selectorCfg); err != nil {
			return nil, fmt.Errorf("error fetching user defined attributes: %w", err)
		}
		return tr.provideLoop, nil
	}
}

type tracesReceiver struct {
	cfg                *beyla.TracesReceiverConfig
	hostID             string
	spanMetricsEnabled bool
	is                 instrumentations.InstrumentationSelection
	input              <-chan []request.Span
	traceAttrs         map[attr.Name]struct{}
	attributeCache     *expirable2.LRU[svc.UID, []attribute.KeyValue]
}

func (tr *tracesReceiver) fetchConstantAttributes(selectorCfg *attributes.SelectorConfig) error {
	var err error
	tr.traceAttrs, err = tracesgen.UserSelectedAttributes(selectorCfg)
	if err != nil {
		return err
	}

	if tr.spanMetricsEnabled {
		tr.traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return nil
}

func (tr *tracesReceiver) provideLoop(ctx context.Context) {
	sampler := tr.cfg.Sampler.Implementation()

	for {
		select {
		case <-ctx.Done():
			return
		case spans, ok := <-tr.input:
			if !ok {
				return
			}
			spanGroups := tracesgen.GroupSpans(ctx, spans, tr.traceAttrs, sampler, tr.is)
			for _, spanGroup := range spanGroups {
				if len(spanGroup) > 0 {
					sample := spanGroup[0]
					if !sample.Span.Service.ExportModes.CanExportTraces() {
						continue
					}

					envResourceAttrs := otelcfg.ResourceAttrsFromEnv(&sample.Span.Service)
					for _, tc := range tr.cfg.Traces {
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
