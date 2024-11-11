package alloy

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// TracesReceiver creates a terminal node that consumes request.Spans and sends OpenTelemetry traces to the configured consumers.
func TracesReceiver(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *beyla.Config,
	userAttribSelection attributes.Selection,
) pipe.FinalProvider[[]request.Span] {
	return (&tracesReceiver{ctx: ctx, cfg: cfg, attributes: userAttribSelection, hostID: ctxInfo.HostID}).provideLoop
}

type tracesReceiver struct {
	ctx        context.Context
	cfg        *beyla.Config
	attributes attributes.Selection
	hostID     string
}

func (tr *tracesReceiver) spanDiscarded(span *request.Span) bool {
	return span.IgnoreTraces() || span.ServiceID.ExportsOTelTraces()
}

func (tr *tracesReceiver) provideLoop() (pipe.FinalFunc[[]request.Span], error) {
	if !tr.cfg.TracesReceiver.Enabled() {
		return pipe.IgnoreFinal[[]request.Span](), nil
	}
	return func(in <-chan []request.Span) {
		// Get user attributes
		traceAttrs, err := otel.GetUserSelectedAttributes(tr.attributes)
		if err != nil {
			slog.Error("error fetching user defined attributes", "error", err)
		}

		for spans := range in {
			for i := range spans {
				span := &spans[i]
				if tr.spanDiscarded(span) {
					continue
				}
				envResourceAttrs := otel.ResourceAttrsFromEnv(&span.ServiceID)

				for _, tc := range tr.cfg.TracesReceiver.Traces {
					traces := otel.GenerateTraces(tr.cfg.Traces, span, tr.hostID, traceAttrs, envResourceAttrs)
					err := tc.ConsumeTraces(tr.ctx, traces)
					if err != nil {
						slog.Error("error sending trace to consumer", "error", err)
					}
				}
			}
		}
	}, nil
}
