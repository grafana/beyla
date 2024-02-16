package grafagent

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/beyla/pkg/internal/request"
)

type traceConsumer interface {
	ConsumeTraces(ctx context.Context, traces ptrace.Traces)
}

type TracesExporterConfig struct {
	Context  context.Context
	Consumer traceConsumer
}

func TracesExporterProvider(cfg *TracesExporterConfig) (node.TerminalFunc[[]*request.Span], error) {
	return func(in <-chan []*request.Span) {
		for i := range in {
			cfg.Consumer.ConsumeTraces(cfg.Context, convert(i))
		}
	}, nil
}

func convert([]*request.Span) ptrace.Traces {
	trace := ptrace.NewTraces()
	trace.ResourceSpans().
	return ptrace.Traces{}
}
