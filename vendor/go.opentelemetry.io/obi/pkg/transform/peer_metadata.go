// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/internal/traces"
	"go.opentelemetry.io/obi/pkg/metadata/peer"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

func PeerMetadataProvider(ctxInfo *global.ContextInfo, cfg peer.MetadataConfig, instance config.InstanceIDConfig, serviceGraphEnabled bool,
	metricProtocols *instrumentations.InstrumentationSelection,
	processEvents *msg.Queue[exec.ProcessEvent], input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled || ctxInfo.K8sInformer != nil && ctxInfo.K8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}

		hostname := traces.NewHostInstance(&instance).HostName
		var metricsPIDs selection.PIDSelector
		if ctxInfo.DynamicSelector != nil {
			metricsPIDs = ctxInfo.DynamicSelector.AppMetrics()
		}
		agent, err := peer.New(ctx, cfg, hostname, serviceGraphEnabled, metricsPIDs, metricProtocols)
		if err != nil {
			return nil, err
		}

		events := processEvents.Subscribe(msg.SubscriberName("PeerMetadata"))
		spans := input.Subscribe(msg.SubscriberName("PeerMetadata"))
		return func(ctx context.Context) {
			defer output.Close()
			runCtx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() { defer close(done); agent.Run(runCtx, events) }()
			defer func() { cancel(); <-done }()

			swarms.ForEachInput(ctx, spans, nil, func(batch []request.Span) {
				now := time.Now()
				for i := range batch {
					agent.Decorate(&batch[i], now)
				}
				output.SendCtx(ctx, batch)
			})
		}, nil
	}
}
