package infraolly

import (
	"context"
	"fmt"
	"slices"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/request"
)

// SubPipeline is actually a part of the Application Observability pipeline.
// Its management is moved here because it's only activated if the process
// metrics are activated.
type subPipeline struct {
	Collector  pipe.Start[[]*process.Status]
	OtelExport pipe.Final[[]*process.Status]
	PromExport pipe.Final[[]*process.Status]
}

func collector(sp *subPipeline) *pipe.Start[[]*process.Status]  { return &sp.Collector }
func otelExport(sp *subPipeline) *pipe.Final[[]*process.Status] { return &sp.OtelExport }
func promExport(sp *subPipeline) *pipe.Final[[]*process.Status] { return &sp.PromExport }

func (sp *subPipeline) Connect() {
	sp.Collector.SendTo(sp.OtelExport, sp.PromExport)
}

// the sub-pipe is enabled only if there is a metrics exporter enabled,
// and both the "application" and "application_process" features are enabled
func isSubPipeEnabled(cfg *beyla.Config) bool {
	return (cfg.Metrics.EndpointEnabled() && cfg.Metrics.AppMetricsEnabled() &&
		slices.Contains(cfg.Metrics.Features, otel.FeatureProcess)) ||
		(cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.AppMetricsEnabled() &&
			slices.Contains(cfg.Prometheus.Features, otel.FeatureProcess))
}

// SubPipelineProvider returns a Final node that actually has a pipeline inside.
// It is manually connected through a channel
func SubPipelineProvider(ctx context.Context, cfg *beyla.Config) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !isSubPipeEnabled(cfg) {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		connectorChan := make(chan []request.Span, cfg.ChannelBufferLen)
		var connector <-chan []request.Span = connectorChan
		nb := pipe.NewBuilder(&subPipeline{}, pipe.ChannelBufferLen(cfg.ChannelBufferLen))
		pipe.AddStartProvider(nb, collector, process.NewCollectorProvider(ctx, &connector, &cfg.Processes))
		pipe.AddFinal(nb, otelExport, func(in <-chan []*process.Status) {
			for i := range in {
				fmt.Printf("otel %#v\n", i)
			}
		})
		pipe.AddFinal(nb, promExport, func(in <-chan []*process.Status) {
			for ps := range in {
				for _, p := range ps {
					fmt.Printf("%#v\n", *p)
				}
			}
		})

		runner, err := nb.Build()
		if err != nil {
			return nil, fmt.Errorf("creating process subpipeline: %w", err)
		}
		return func(in <-chan []request.Span) {
			connector = in
			runner.Start()
			<-ctx.Done()
		}, nil
	}
}