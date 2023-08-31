package traces

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
)

// Reader is the input node of the processing graph. The eBPF tracers will send their
// traces to the Reader's TracesInput, and the Reader will forward them to the next
// pipeline stage
type Reader struct {
	TracesInput <-chan []request.Span
}

func ReaderProvider(_ context.Context, r Reader) (node.StartFuncCtx[[]request.Span], error) {
	return func(ctx context.Context, out chan<- []request.Span) {
		for trace := range r.TracesInput {
			out <- trace
		}
	}, nil
}
