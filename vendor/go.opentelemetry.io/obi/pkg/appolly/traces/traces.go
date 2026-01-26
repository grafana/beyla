// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/traces"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func rlog() *slog.Logger {
	return slog.With("component", "HostProcessEventDecoratorProvider")
}

func HostProcessEventDecoratorProvider(
	cfg *config.InstanceIDConfig,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		decorate := traces.HostNamePIDDecorator(cfg)
		in := input.Subscribe(msg.SubscriberName("HostProcessEventDecorator"))
		// if kubernetes decoration is disabled, we just bypass the node
		log := rlog().With("function", "HostProcessEventDecoratorProvider")
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, log.Debug, func(pe exec.ProcessEvent) {
				decorate(&pe.File.Service, int(pe.File.Pid))
				log.Debug("host decorating event", "event", pe, "ns", pe.File.Ns, "procPID", pe.File.Pid, "procPPID", pe.File.Ppid, "service", pe.File.Service.UID)
				output.Send(pe)
			})
		}, nil
	}
}
