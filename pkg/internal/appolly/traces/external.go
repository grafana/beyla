package traces

import (
	"context"
	"log/slog"
	"net/netip"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// SelectExternal node filters spans whose source or destination could not be
// resolved, indicating that they mighg belong to connections from/to external
// services.
func SelectExternal(input, out *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	in := input.Subscribe()
	return swarm.DirectInstance(func(ctx context.Context) {
		log := slog.With("component", "traces.SelectExternal")
		defer out.Close()
		swarms.ForEachInput(ctx, in, log.Debug, func(spans []request.Span) {
			if extern := filter(spans); len(extern) > 0 {
				out.Send(extern)
			}
		})
	})
}

func filter(spans []request.Span) []request.Span {
	var extern []request.Span
	for i := range spans {
		if isExternalSelectable(&spans[i]) {
			extern = append(extern, spans[i])
		}
	}
	return extern
}

// this code might not work if the eBPF-based reverse DNS is enabled and it hits a known host name.
func isExternalSelectable(span *request.Span) bool {
	isClient := span.IsClientSpan()
	return span.TraceID.IsValid() &&
		((!isClient && validPublicIP(span.PeerName)) ||
			(isClient && validPublicIP(span.HostName)))
}

func validPublicIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.IsValid() && !addr.IsPrivate()
}
