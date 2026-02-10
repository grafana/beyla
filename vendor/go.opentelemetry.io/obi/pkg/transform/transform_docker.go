// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transform // import "go.opentelemetry.io/obi/pkg/transform"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/docker"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func delog() *slog.Logger {
	return slog.With("component", "transform.DockerEnricher")
}

func DockerDecoratorProvider(
	ctxInfo *global.ContextInfo,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		// only enable this node if Docker is available, but also
		// if we aren't running on Kubernetes
		if ctxInfo.K8sInformer.IsKubeEnabled() ||
			!ctxInfo.DockerMetadata.IsEnabled(ctx) {
			return swarm.Bypass(input, output)
		}

		dd := dockerEnricher{
			in:             input.Subscribe(msg.SubscriberName("DockerEnricher")),
			out:            output,
			containerByPID: map[app.PID]docker.ContainerMeta{},
			log:            delog(),
			docker:         ctxInfo.DockerMetadata,
		}
		return dd.decorate, nil
	}
}

type dockerEnricher struct {
	in             <-chan []request.Span
	out            *msg.Queue[[]request.Span]
	containerByPID map[app.PID]docker.ContainerMeta
	log            *slog.Logger
	docker         *docker.ContainerStore
}

func (dd *dockerEnricher) decorate(ctx context.Context) {
	defer dd.out.Close()
	swarms.ForEachInput(ctx, dd.in, dd.log.Debug, func(spans []request.Span) {
		for i := range spans {
			svc := &spans[i].Service
			if ci, ok := dd.containerInfo(ctx, svc.ProcPID); ok {
				ci.DecorateService(svc)
			}
		}
		dd.out.SendCtx(ctx, spans)
	})
}

func (dd *dockerEnricher) containerInfo(ctx context.Context, pid app.PID) (docker.ContainerMeta, bool) {
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

func dpelog() *slog.Logger {
	return slog.With("component", "transform.DockerProcessEventDecorator")
}

func DockerProcessEventDecoratorProvider(
	ctxInfo *global.ContextInfo,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		// only enable this node if Docker is available, but also
		// if we aren't running on Kubernetes
		if ctxInfo.K8sInformer.IsKubeEnabled() ||
			!ctxInfo.DockerMetadata.IsEnabled(ctx) {
			return swarm.Bypass(input, output)
		}

		in := input.Subscribe()
		containers := ctxInfo.DockerMetadata
		containerByPID := map[app.PID]docker.ContainerMeta{}

		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, dpelog().Debug, func(ev exec.ProcessEvent) {
				if ev.File == nil {
					return
				}
				switch ev.Type {
				case exec.ProcessEventCreated:
					ci, ok := containerByPID[ev.File.Pid]
					if !ok {
						if ci, ok = containers.ContainerInfo(ctx, ev.File.Pid); ok {
							containerByPID[ev.File.Pid] = ci
						}
					}
					if ok {
						ci.DecorateService(&ev.File.Service)
					}
				case exec.ProcessEventTerminated:
					delete(containerByPID, ev.File.Pid)
				}
				output.SendCtx(ctx, ev)
			})
		}, nil
	}
}
