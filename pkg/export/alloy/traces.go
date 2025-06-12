package alloy

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	expirable2 "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/instrumentations"
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
			input: input.Subscribe(),
			is: instrumentations.NewInstrumentationSelection([]string{
				instrumentations.InstrumentationALL,
			}),
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
	tr.traceAttrs, err = otel.GetUserSelectedAttributes(selectorCfg)
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
			spanGroups := otel.GroupSpans(ctx, spans, tr.traceAttrs, sampler, tr.is)
			for _, spanGroup := range spanGroups {
				if len(spanGroup) > 0 {
					sample := spanGroup[0]
					envResourceAttrs := otel.ResourceAttrsFromEnv(&sample.Span.Service)
					for _, tc := range tr.cfg.Traces {
						traces := otel.GenerateTraces(tr.attributeCache, &sample.Span.Service, envResourceAttrs, tr.hostID, spanGroup)
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
