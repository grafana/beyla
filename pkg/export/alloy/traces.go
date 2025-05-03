package alloy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/grafana/beyla/v2/pkg/pipe/msg"
	"github.com/grafana/beyla/v2/pkg/pipe/swarm"
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
	input              <-chan []request.Span
	traceAttrs         map[attr.Name]struct{}
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

func (tr *tracesReceiver) spanDiscarded(span *request.Span) bool {
	return span.IgnoreTraces() || span.Service.ExportsOTelTraces()
}

func (tr *tracesReceiver) provideLoop(ctx context.Context) {
	for spans := range tr.input {
		for i := range spans {
			span := &spans[i]
			if tr.spanDiscarded(span) {
				continue
			}
			envResourceAttrs := otel.ResourceAttrsFromEnv(&span.Service)

			for _, tc := range tr.cfg.Traces {
				traces := otel.GenerateTraces(span, tr.hostID, tr.traceAttrs, envResourceAttrs)
				err := tc.ConsumeTraces(ctx, traces)
				if err != nil {
					slog.Error("error sending trace to consumer", "error", err)
				}
			}
		}
	}
}
