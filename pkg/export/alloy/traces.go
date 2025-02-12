package alloy

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/export/attributes"
	attr "github.com/grafana/beyla/pkg/export/attributes/names"
	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *beyla.TracesReceiverConfig,
	spanMetricsEnabled bool,
	userAttribSelection attributes.Selection,
) pipe.FinalProvider[[]request.Span] {
	return (&tracesReceiver{ctx: ctx, cfg: cfg, attributes: userAttribSelection, hostID: ctxInfo.HostID, spanMetricsEnabled: spanMetricsEnabled}).provideLoop
}

type tracesReceiver struct {
	ctx                context.Context
	cfg                *beyla.TracesReceiverConfig
	attributes         attributes.Selection
	hostID             string
	spanMetricsEnabled bool
}

func (tr *tracesReceiver) getConstantAttributes() (map[attr.Name]struct{}, error) {
	traceAttrs, err := otel.GetUserSelectedAttributes(tr.attributes)
	if err != nil {
		return nil, err
	}

	if tr.spanMetricsEnabled {
		traceAttrs[attr.SkipSpanMetrics] = struct{}{}
	}
	return traceAttrs, nil
}

func (tr *tracesReceiver) spanDiscarded(span *request.Span) bool {
	return span.IgnoreTraces() || span.Service.ExportsOTelTraces()
}

func (tr *tracesReceiver) provideLoop() (pipe.FinalFunc[[]request.Span], error) {
	if !tr.cfg.Enabled() {
		return pipe.IgnoreFinal[[]request.Span](), nil
	}
	return func(in <-chan []request.Span) {
		// Get user attributes
		traceAttrs, err := tr.getConstantAttributes()
		if err != nil {
			slog.Error("error fetching user defined attributes", "error", err)
		}

		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if tr.spanDiscarded(span) {
					continue
				}
				envResourceAttrs := otel.ResourceAttrsFromEnv(&span.Service)

				for _, tc := range tr.cfg.Traces {
					traces := otel.GenerateTraces(span, tr.hostID, traceAttrs, envResourceAttrs)
					err := tc.ConsumeTraces(tr.ctx, traces)
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}
