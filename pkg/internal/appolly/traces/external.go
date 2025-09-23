package traces

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"

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
			bytes, err := json.Marshal(span)
			fmt.Println("---", err)
			fmt.Println(string(bytes))
			fmt.Println("---")
			extern = append(extern, span)
		}
	}
	return extern
}

// this code might not work if the reverse DNS is enabled and it hits a known host name.
// TODO: We might need to add extra ResolvedHostName and ResolvedPeerName fields to the Span struct
func isExternalSelectable(span *request.Span) bool {
	return span.TraceID.IsValid() && // what about span.ParentSpanID?
		validPublicIP(span.PeerName)
}

func validPublicIP(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.IsValid() && !addr.IsPrivate()
}