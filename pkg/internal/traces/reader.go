package traces

import (
	"context"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
)

func rlog() *slog.Logger {
	return slog.With("component", "traces.Reader")
}

// Reader is the input node of the processing graph. The eBPF tracers will send their
// traces to the Reader's TracesInput, and the Reader will forward them to the next
// pipeline stage
type Reader struct {
	TracesInput <-chan []request.Span
}

func ReadFromChannel(ctx context.Context, r Reader) (node.StartFunc[[]request.Span], error) {
	return func(out chan<- []request.Span) {
		cancelChan := ctx.Done()
		for {
			select {
			case trace, ok := <-r.TracesInput:
				if ok {
					out <- trace
				} else {
					rlog().Debug("input channel closed. Exiting traces input loop")
					return
				}
			case <-cancelChan:
				rlog().Debug("context canceled. Exiting traces input loop")
				return
			}
		}
	}, nil
}
