package grafagent

import (
	"github.com/mariomac/pipes/pkg/node"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/request"
)

// type traceConsumer interface {
// 	otelconsumer.Traces
// }

func TracesExporterProvider(cfg beyla.TracesExporterConfig) (node.TerminalFunc[[]*request.Span], error) {
	return func(in <-chan []*request.Span) {
		for i := range in {
			cfg.Consumer.ConsumeTraces(cfg.Context, convert(i))
		}
	}, nil
}

func convert(spans []*request.Span) ptrace.Traces {
	traces := ptrace.NewTraces()

	for _, span := range spans {
		rs := traces.ResourceSpans().AppendEmpty()
		res := rs.Resource()
		attrs := otel.TraceAttributes(span)
		for _, kv := range attrs {
			res.Attributes().PutStr(string(kv.Key), kv.Value.AsString())
		}
	}
	return traces
}
