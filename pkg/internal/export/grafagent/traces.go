package grafagent

import (
	"context"

	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/beyla/pkg/internal/request"
	otelconsumer "go.opentelemetry.io/collector/consumer"
)

// type traceConsumer interface {
// 	otelconsumer.Traces
// }

type TracesExporterConfig struct {
	Context  context.Context
	Consumer otelconsumer.Traces
}

func TracesExporterProvider(cfg *TracesExporterConfig) (node.TerminalFunc[[]*request.Span], error) {
	return func(in <-chan []*request.Span) {
		for i := range in {
			cfg.Consumer.ConsumeTraces(cfg.Context, convert(i))
		}
	}, nil
}

func convert([]*request.Span) ptrace.Traces {
	traces := ptrace.NewTraces()
	return traces
}
