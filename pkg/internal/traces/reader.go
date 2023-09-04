package traces

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"
)

// Reader is the input node of the processing graph. The eBPF tracers will send their
// traces to the Reader's TracesInput, and the Reader will forward them to the next
// pipeline stage
type Reader struct {
	TracesInput <-chan []any
}

func ReaderProvider(_ context.Context, r Reader) (node.StartFuncCtx[[]any], error) {
	return func(ctx context.Context, out chan<- []any) {
		for trace := range r.TracesInput {
			out <- trace
		}
	}, nil
}
