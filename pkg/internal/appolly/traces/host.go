package traces

import (
	"context"
	"log/slog"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"

	"github.com/grafana/beyla/v3/pkg/export/extraattributes/names"
)

// DecorateHostID supplies the Grafana host identity consumed by both span-metric exporters.
func DecorateHostID(hostID string, input, out *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	in := input.Subscribe(msg.SubscriberName("traces.DecorateHostID"))
	return swarm.DirectInstance(func(ctx context.Context) {
		defer out.Close()
		swarms.ForEachInput(ctx, in, slog.Debug, func(spans []request.Span) {
			// Services and batches can be shared with other queue subscribers.
			decorated := slices.Clone(spans)
			for i := range decorated {
				svc := &decorated[i].Service
				if svc.Metadata == nil {
					svc.Metadata = map[attr.Name]string{}
				}
				svc.Metadata[names.GrafanaHostID] = hostID
			}
			out.SendCtx(ctx, decorated)
		})
	})
}
