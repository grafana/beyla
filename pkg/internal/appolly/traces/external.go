package traces

import (
	"context"
	"log/slog"
	"net"

	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func SelectExternal(input, out *msg.Queue[[]request.Span]) swarm.InstanceFunc {
	in := input.Subscribe()
	return swarm.DirectInstance(func(ctx context.Context) {
		log := slog.With("component", "traces.SelectExternal")
		defer out.Close()
		log.Debug("starting")
		for {
			select {
			case <-ctx.Done():
				log.Debug("context canceled. Exiting")
				return
			case spans, ok := <-in:
				if !ok {
					log.Debug("input channel closed. Exiting")
					return
				}
				if extern := filter(spans); len(extern) > 0 {
					out.Send(extern)
				}
			}
		}
	})
}

func filter(spans []request.Span) []request.Span {
	var extern []request.Span
	for _, span := range spans {
		if isExternalSelectable(&span) {
			externalSpan := span
			externalSpan.Service.Metadata["chirrifluski"] = "tracatra"
			extern = append(extern, externalSpan)
		}
	}
	return extern
}

// this code might not work if the reverse DNS is enabled and it hits a known host name.
// TODO: We might need to add extra ResolvedHostName and ResolvedPeerName fields to the Span struct
func isExternalSelectable(span *request.Span) bool {
	return span.TraceID.IsValid() && // what about span.ParentSpanID?
		((span.HostName != "" && net.ParseIP(span.HostName) != nil) ||
			(span.HostName == "" && span.Host != "" && net.ParseIP(span.Host) != nil) ||
			(span.PeerName != "" && net.ParseIP(span.PeerName) != nil) ||
			(span.PeerName == "" && span.Peer != "" && net.ParseIP(span.Peer) != nil))
}
