// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/ebpf"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// ContainerStoreUpdaterProvider is a stage in the Process Finder pipeline that will be
// enabled only if Kubernetes decoration is enabled.
// It just updates part of the kubernetes store when a new process is discovered.
// TODO: rename to avoid confusions with Docker-only containers
func ContainerStoreUpdaterProvider(
	meta kubeMetadataProvider, input, output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !meta.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		store, err := meta.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating ContainerStoreUpdater: %w", err)
		}
		return updateLoop(store, input.Subscribe(msg.SubscriberName("ContainerStoreUpdater")), output), nil
	}
}

func updateLoop(
	store *kube.Store, in <-chan []Event[ebpf.Instrumentable], out *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.RunFunc {
	log := slog.With("component", "ContainerStoreUpdater")
	return func(ctx context.Context) {
		defer out.Close()
		swarms.ForEachInput(ctx, in, log.Debug, func(instrumentables []Event[ebpf.Instrumentable]) {
			for i := range instrumentables {
				ev := &instrumentables[i]
				switch ev.Type {
				case EventCreated:
					log.Debug("adding process", "pid", ev.Obj.FileInfo.Pid())
					store.AddProcess(ev.Obj.FileInfo.Pid())
				case EventDeleted:
					log.Debug("deleting process", "pid", ev.Obj.FileInfo.Pid())
					// Apply deletion in this stage's event order so a delayed create cannot
					// restore stale PID state after upstream cleanup.
					store.DeleteProcess(ev.Obj.FileInfo.Pid())
				}
			}
			out.SendCtx(ctx, instrumentables)
		})
	}
}
