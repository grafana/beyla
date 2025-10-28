// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"context"
	"log/slog"
	"strconv"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/traces/hostname"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rlog() *slog.Logger {
	return slog.With("component", "traces.ReadDecorator")
}

// ReadDecorator is the input node of the processing graph. The eBPF tracers will send their
// traces to the ReadDecorator's TracesInput, and the ReadDecorator will decorate the traces with some
// basic information (e.g. instance ID) and forward them to the next pipeline stage
type ReadDecorator struct {
	TracesInput     *msg.Queue[[]request.Span]
	DecoratedTraces *msg.Queue[[]request.Span]

	InstanceID config.InstanceIDConfig
}

func ReadFromChannel(r *ReadDecorator) swarm.InstanceFunc {
	decorate := HostNamePIDDecorator(&r.InstanceID)
	tracesInput := r.TracesInput.Subscribe(msg.SubscriberName("traces.ReadDecorator"))
	return swarm.DirectInstance(func(ctx context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer r.DecoratedTraces.Close()
		cancelChan := ctx.Done()
		out := r.DecoratedTraces
		for {
			select {
			case traces, ok := <-tracesInput:
				if ok {
					for i := range traces {
						decorate(&traces[i].Service, int(traces[i].Pid.HostPID))
					}
					out.Send(traces)
				} else {
					rlog().Debug("input channel closed. Exiting traces input loop")
					return
				}
			case <-cancelChan:
				rlog().Debug("context canceled. Exiting traces input loop")
				return
			}
		}
	})
}

// Decorator modifies a []request.Span slice to fill it with extra information that is not provided
// by the tracers (for example, the instance ID)
type Decorator func(s *svc.Attrs, pid int)

func HostNamePIDDecorator(cfg *config.InstanceIDConfig) Decorator {
	// TODO: periodically update in case the current Beyla instance is created from a VM snapshot running as a different hostname
	resolver := hostname.CreateResolver(cfg.OverrideHostname, "", cfg.HostnameDNSResolution)
	fullHostName, _, err := resolver.Query()
	log := rlog().With("function", "instance_ID_hostNamePIDDecorator")
	if err != nil {
		log.Warn("can't read hostname. Leaving empty. Consider overriding"+
			" the OTEL_EBPF_HOSTNAME property", "error", err)
	} else {
		log.Info("using hostname", "hostname", fullHostName)
	}

	// caching instance ID composition for speed and saving memory generation
	return func(s *svc.Attrs, hostPID int) {
		s.UID.Instance = fullHostName + ":" + strconv.Itoa(hostPID)
		s.HostName = fullHostName
	}
}
