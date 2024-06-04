package process

import (
	"context"
	"fmt"
	"slices"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// processSubPipeline is actually a part of the Application Observability pipeline.
// Its management is moved here because it's only activated if the process
// metrics are activated.
type processSubPipeline struct {
	Collector  pipe.Start[[]*Status]
	OtelExport pipe.Final[[]*Status]
	// TODO: add prometheus exporter
}

func collector(sp *processSubPipeline) *pipe.Start[[]*Status]  { return &sp.Collector }
func otelExport(sp *processSubPipeline) *pipe.Final[[]*Status] { return &sp.OtelExport }

func (sp *processSubPipeline) Connect() {
	sp.Collector.SendTo(sp.OtelExport)
}

// the sub-pipe is enabled only if there is a metrics exporter enabled,
// and both the "application" and "application_process" features are enabled
func isSubPipeEnabled(cfg *beyla.Config) bool {
	return (cfg.Metrics.EndpointEnabled() && cfg.Metrics.OTelMetricsEnabled() &&
		slices.Contains(cfg.Metrics.Features, otel.FeatureProcess)) ||
		(cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.OTelMetricsEnabled() &&
			slices.Contains(cfg.Prometheus.Features, otel.FeatureProcess))
}

// SubPipelineProvider returns a Final node that actually has a pipeline inside.
// It is manually connected through a channel
func SubPipelineProvider(ctx context.Context, ctxInfo *global.ContextInfo, cfg *beyla.Config) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !isSubPipeEnabled(cfg) {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		connectorChan := make(chan []request.Span, cfg.ChannelBufferLen)
		var connector <-chan []request.Span = connectorChan
		nb := pipe.NewBuilder(&processSubPipeline{}, pipe.ChannelBufferLen(cfg.ChannelBufferLen))
		pipe.AddStartProvider(nb, collector, NewCollectorProvider(ctx, &connector, &cfg.Processes))
		pipe.AddFinalProvider(nb, otelExport, otel.ProcMetricsExporterProvider(ctx, ctxInfo,
			&otel.ProcMetricsConfig{
				Metrics:            &cfg.Metrics,
				AttributeSelectors: cfg.Attributes.Select,
			}))

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
