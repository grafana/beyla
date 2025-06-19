package pipe

import (
	"context"
	"fmt"
	"slices"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	attributes "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
)

// the sub-pipe is enabled only if there is a metrics exporter enabled,
// and both the "application" and "application_process" features are enabled
func isProcessSubPipeEnabled(cfg *beyla.Config) bool {
	return (cfg.Metrics.EndpointEnabled() && cfg.Metrics.OTelMetricsEnabled() &&
		slices.Contains(cfg.Metrics.Features, otel.FeatureProcess)) ||
		(cfg.Prometheus.EndpointEnabled() && cfg.Prometheus.OTelMetricsEnabled() &&
			slices.Contains(cfg.Prometheus.Features, otel.FeatureProcess))
}

// ProcessMetricsSwarmInstancer returns a swarm.Instancer that actually has contains another swarm.Instancer
// inside of it.
func ProcessMetricsSwarmInstancer(
	ctxInfo *global.ContextInfo,
	cfg *beyla.Config,
	appInputSpans *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	if !isProcessSubPipeEnabled(cfg) {
		// returns nothing. Nothing will subscribe to the ProcessSubPipeInput, no extra
		// load will be held
		return swarm.DirectInstance(func(_ context.Context) {})
	}
	// needs to be instantiated here to make sure all the messages from the
	// vendored OBI app swarm are catched
	appInputSpansCh := appInputSpans.Subscribe()
	return func(ctx context.Context) (swarm.RunFunc, error) {
		selectorCfg := &attributes.SelectorConfig{
			SelectionCfg:            cfg.Attributes.Select,
			ExtraGroupAttributesCfg: cfg.Attributes.ExtraGroupAttributes,
		}

		// communication channel between the process collector and the metrics exporters
		processCollectStatus := msg.NewQueue[[]*process.Status](msg.ChannelBufferLen(cfg.ChannelBufferLen))

		builder := swarm.Instancer{}
		builder.Add(process.NewCollectorProvider(
			&cfg.Processes,
			appInputSpansCh,
			processCollectStatus,
		))
		builder.Add(otel.ProcMetricsExporterProvider(
			ctxInfo,
			&otel.ProcMetricsConfig{
				Metrics:     &cfg.Metrics,
				SelectorCfg: selectorCfg,
			},
			processCollectStatus,
		))
		builder.Add(prom.ProcPrometheusEndpoint(ctxInfo,
			&prom.ProcPrometheusConfig{
				Metrics:     &cfg.Prometheus,
				SelectorCfg: selectorCfg,
			},
			processCollectStatus,
		))
		runner, err := builder.Instance(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create the process pipeline: %w", err)
		}
		return func(ctx context.Context) { runner.Start(ctx) }, nil
	}
}
