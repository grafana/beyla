package traces

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func SelectGenAI(input, out *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	in := input.Subscribe(msg.SubscriberName("traces.SelectGenAI"))
	return swarm.DirectInstance(func(ctx context.Context) {
		log := slog.With("component", "traces.SelectGenAI")
		defer out.Close()
		swarms.ForEachInput(ctx, in, log.Debug, func(spans []request.Span) {
			if genAI := filterGenAI(spans); len(genAI) > 0 {
				out.SendCtx(ctx, genAI)
			}
		})
	})
}

func filterGenAI(spans []request.Span) []request.Span {
	var genAI []request.Span
	for i := range spans {
		if spans[i].Service.ExportModes.CanExportTraces() &&
			request.IsGenAISubtype(spans[i].SubType) {
			genAI = append(genAI, spans[i])
		}
	}
	return genAI
}
