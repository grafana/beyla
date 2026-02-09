// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/docker"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func ddlog() *slog.Logger {
	return slog.With("component", "DockerDecorator")
}

type dockerAPIClient interface {
	IsEnabled(context.Context) bool
	ContainerInfo(context.Context, app.PID) (docker.ContainerMeta, bool)
}

func DockerDiscoveryDecoratorProvider(
	kube kubeMetadataProvider,
	dockerClient dockerAPIClient,
	input, output *msg.Queue[[]Event[ProcessAttrs]],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		// only enable this node if Docker is available, but also
		// if we aren't running on Kubernetes
		if kube.IsKubeEnabled() ||
			!dockerClient.IsEnabled(ctx) {
			return swarm.Bypass(input, output)
		}

		dd := dockerDecorator{
			in:             input.Subscribe(msg.SubscriberName("DockerDecorator")),
			out:            output,
			containerByPID: map[app.PID]docker.ContainerMeta{},
			log:            ddlog(),
			docker:         dockerClient,
		}
		return dd.decorate, nil
	}
}

type dockerDecorator struct {
	in             <-chan []Event[ProcessAttrs]
	out            *msg.Queue[[]Event[ProcessAttrs]]
	containerByPID map[app.PID]docker.ContainerMeta
	log            *slog.Logger
	docker         dockerAPIClient
}

func (dd *dockerDecorator) decorate(ctx context.Context) {
	defer dd.out.Close()
	swarms.ForEachInput(ctx, dd.in, dd.log.Debug, func(instrumentables []Event[ProcessAttrs]) {
		for i := range instrumentables {
			ev := &instrumentables[i]
			switch ev.Type {
			case EventCreated:
				meta, ok := dd.containerInfo(ctx, ev.Obj.pid)
				if ok {
					ev.Obj.metadata = docker.ContainerMetadata(ev.Obj.metadata, &meta, attr.Name.Prom)
				}
			case EventDeleted:
				delete(dd.containerByPID, ev.Obj.pid)
			}
		}
		dd.out.SendCtx(ctx, instrumentables)
	})
}

func (dd *dockerDecorator) containerInfo(ctx context.Context, pid app.PID) (docker.ContainerMeta, bool) {
	if ci, ok := dd.containerByPID[pid]; ok {
		return ci, true
	}
	ci, ok := dd.docker.ContainerInfo(ctx, pid)
	if ok {
		dd.containerByPID[pid] = ci
	} else {
		dd.log.Debug("can't find container metadata", "pid", pid)
	}
	return ci, ok
}
