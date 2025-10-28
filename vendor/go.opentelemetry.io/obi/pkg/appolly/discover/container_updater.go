// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

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

// ContainerDBUpdaterProvider is a stage in the Process Finder pipeline that will be
// enabled only if Kubernetes decoration is enabled.
// It just updates part of the kubernetes database when a new process is discovered.
func ContainerDBUpdaterProvider(
	meta kubeMetadataProvider, input, output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !meta.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		store, err := meta.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("instantiating ContainerDBUpdater: %w", err)
		}
		return updateLoop(store, input.Subscribe(msg.SubscriberName("ContainerDBUpdater")), output), nil
	}
}

func updateLoop(
	db *kube.Store, in <-chan []Event[ebpf.Instrumentable], out *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.RunFunc {
	log := slog.With("component", "ContainerDBUpdater")
	return func(ctx context.Context) {
		defer out.Close()
		swarms.ForEachInput(ctx, in, log.Debug, func(instrumentables []Event[ebpf.Instrumentable]) {
			for i := range instrumentables {
				ev := &instrumentables[i]
				switch ev.Type {
				case EventCreated:
					log.Debug("adding process", "pid", ev.Obj.FileInfo.Pid)
					db.AddProcess(uint32(ev.Obj.FileInfo.Pid))
				case EventDeleted:
					// we don't need to handle process deletion from here, as the Kubernetes informer will
					// remove the process from the database when the Pod that contains it is deleted.
				}
			}
			out.Send(instrumentables)
		})
	}
}
