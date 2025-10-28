package pipe

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"go.opentelemetry.io/obi/pkg/appolly"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/alloy"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/otel/spanscfg"
	"github.com/grafana/beyla/v2/pkg/internal/appolly/traces"
)

func ilog() *slog.Logger {
	return slog.With("component", "BeylaInstrumenter")
}

// Build instantiates the whole instrumentation --> processing --> submit
// pipeline graph and returns it as a startable item
func Build(ctx context.Context, config *beyla.Config, ctxInfo *global.ContextInfo, tracesCh *msg.Queue[[]request.Span], processEventsCh *msg.Queue[exec.ProcessEvent]) (*swarm.Runner, error) {
	// a swarm containing two swarms
	// 1. OBI's actual appolly.Build swarm
	// 2. the process metrics swarm pipeline, connected to the output of (1)
	swi := &swarm.Instancer{}
	swi.Add(func(ctx context.Context) (swarm.RunFunc, error) {
		obiSwarm, err := appolly.Build(ctx, config.AsOBI(), ctxInfo, tracesCh, processEventsCh)
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

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            config.Attributes.Select,
		ExtraGroupAttributesCfg: config.Attributes.ExtraGroupAttributes,
	}
	swi.Add(alloy.TracesReceiver(ctxInfo, &config.TracesReceiver, config.Metrics.SpanMetricsEnabled(),
		selectorCfg, ctxInfo.OverrideAppExportQueue))

	clusterConnectorsSubpipeline(swi, ctxInfo, config)

	swi.Add(ProcessMetricsSwarmInstancer(ctxInfo, config, ctxInfo.OverrideAppExportQueue))

	return swi.Instance(ctx)
}

func unresolvedNames(cfg *beyla.Config) request.UnresolvedNames {
	return request.UnresolvedNames{
		Generic:  cfg.Attributes.RenameUnresolvedHosts,
		Outgoing: cfg.Attributes.RenameUnresolvedHostsOutgoing,
		Incoming: cfg.Attributes.RenameUnresolvedHostsIncoming,
	}
}

// clusterConnectorsSubpipeline will submit "connector" traces that are identified as cluster-external.
// Tempo will use them to compose inter-cluster service graph connections that otherwise couldn't be composed by
// Beyla, as it lacks the metadata from the remote clusters.
func clusterConnectorsSubpipeline(swi *swarm.Instancer, ctxInfo *global.ContextInfo, config *beyla.Config) {
	if !slices.Contains(config.Topology.Spans, spanscfg.TopologyInterCluster) {
		return
	}
	// we currently only support this feature for Kubernetes clusters
	if ctxInfo.K8sInformer == nil || !ctxInfo.K8sInformer.IsKubeEnabled() {
		return
	}

	store, err := ctxInfo.K8sInformer.Get(context.Background())
	if err != nil {
		ilog().Error("can't get Kubernetes store. Connection spans feature is disabled", "error", err)
		return
	}

	externalTraces := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(config.ChannelBufferLen))
	swi.Add(traces.SelectExternal(
		func(ip string) bool { return store.ObjectMetaByIP(ip) != nil },
		ctxInfo.OverrideAppExportQueue,
		externalTraces,
	))

	swi.Add(alloy.ConnectionSpansReceiver(ctxInfo,
		config,
		externalTraces,
	))

	swi.Add(otel.ConnectionSpansExport(ctxInfo,
		&config.Traces,
		unresolvedNames(config),
		externalTraces))
}
