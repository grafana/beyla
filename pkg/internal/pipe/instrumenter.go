package pipe

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/grafana/beyla/v2/pkg/internal/appolly/traces"
	"go.opentelemetry.io/obi/pkg/app/request"
	"go.opentelemetry.io/obi/pkg/components/exec"
	"go.opentelemetry.io/obi/pkg/components/pipe"
	"go.opentelemetry.io/obi/pkg/components/pipe/global"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/services"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/alloy"
)

func ilog() *slog.Logger {
	return slog.With("component", "BeylaInstrumenter")
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh *msg.Queue[[]request.Span], processEventsCh *msg.Queue[exec.ProcessEvent]) (*swarm.Runner, error) {

	if ctxInfo.OverrideAppExportQueue == nil {
		ctxInfo.OverrideAppExportQueue = msg.NewQueue[[]request.Span](
			msg.ChannelBufferLen(config.ChannelBufferLen),
		)
	}
	// a swarm containing two swarms
	// 1. OBI's actual pipe.Build swarm
	// 2. the process metrics swarm pipeline, connected to the output of (1)
	swi := &swarm.Instancer{}
	swi.Add(func(ctx context.Context) (swarm.RunFunc, error) {
		obiSwarm, err := pipe.Build(ctx, config.AsOBI(), ctxInfo, tracesCh, processEventsCh)
		if err != nil {
			return nil, fmt.Errorf("instantiating OBI app pipeline: %w", err)
		}
		return func(ctx context.Context) {
			obiFinished := obiSwarm.Start(ctx)
			select {
			case <-ctx.Done():
				ilog().Debug("context done, stopping OBI internal swarm")
			case <-obiFinished:
				ilog().Debug("OBI internal swarm stopped")
			}
		}, nil
	})

	processSubpipeline(swi, ctxInfo, config)

	clusterConnectorsSubpipeline(swi, ctxInfo, config)

	return swi.Instance(ctx)
}

// processSubpipeline optionally starts another pipeline only to collect and export data
// about the processes of an instrumented application
func processSubpipeline(swi *swarm.Instancer, ctxInfo *global.ContextInfo, config *beyla.Config) {
	swi.Add(ProcessMetricsSwarmInstancer(ctxInfo, config, ctxInfo.OverrideAppExportQueue))

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            config.Attributes.Select,
		ExtraGroupAttributesCfg: config.Attributes.ExtraGroupAttributes,
	}

	swi.Add(alloy.TracesReceiver(ctxInfo, &config.TracesReceiver, config.Metrics.SpanMetricsEnabled(),
		selectorCfg, ctxInfo.OverrideAppExportQueue))
}

// clusterConnectorsSubpipeline will submit "connector" traces that are identified as cluster-external.
// Tempo will use them to compose inter-cluster service graph connections that otherwise couldn't be composed by
// Beyla, as it lacks the metadata from the remote clusters.
func clusterConnectorsSubpipeline(swi *swarm.Instancer, ctxInfo *global.ContextInfo, config *beyla.Config) {
	// if config.ConnectClusters
	// TODO: make sure external spans are not submitted via the regular pipeline
	externalTraces := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))
	swi.Add(traces.SelectExternal(
		ctxInfo.OverrideAppExportQueue,
		externalTraces,
	))

	// aqui hay que zurular mejor nuestro propio traces receiver
	swi.Add(alloy.TracesReceiver(ctxInfo, &beyla.TracesReceiverConfig{
		Traces:           config.TracesReceiver.Traces,
		Instrumentations: config.TracesReceiver.Instrumentations,
		Sampler:          services.SamplerConfig{
			Name: "always_off", // parentbased_always_on?
		},
	}, false,
		&attributes.SelectorConfig{
			SelectionCfg:            config.Attributes.Select,
			ExtraGroupAttributesCfg: config.Attributes.ExtraGroupAttributes,
		},
		ctxInfo.OverrideAppExportQueue,
	))
}
