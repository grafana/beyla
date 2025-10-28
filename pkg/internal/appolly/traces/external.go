package traces

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type isInternalIPFn func(ip string) bool

// SelectExternal node filters spans whose source or destination could not be
// resolved, indicating that they might belong to connections from/to external
// services.
func SelectExternal(isClusterIP isInternalIPFn, input, out *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	in := input.Subscribe()
	esp := externalSpanFilter{isClusterIP: isClusterIP}
	return swarm.DirectInstance(func(ctx context.Context) {
		log := slog.With("component", "traces.SelectExternal")
		defer out.Close()
		swarms.ForEachInput(ctx, in, log.Debug, func(spans []request.Span) {
			if extern := esp.filter(spans); len(extern) > 0 {
				out.Send(extern)
			}
		})
	})
}

type externalSpanFilter struct {
	isClusterIP isInternalIPFn
}

func (esp *externalSpanFilter) filter(spans []request.Span) []request.Span {
	var extern []request.Span
	for i := range spans {
		if esp.isExternalSelectable(&spans[i]) {
			extern = append(extern, spans[i])
		}
	}
	return extern
}

func (esp *externalSpanFilter) isExternalSelectable(span *request.Span) bool {
	isClient := span.IsClientSpan()
	return span.TraceID.IsValid() &&
		((!isClient && !esp.isClusterIP(span.Peer)) ||
			(isClient && !esp.isClusterIP(span.Host)))
}
