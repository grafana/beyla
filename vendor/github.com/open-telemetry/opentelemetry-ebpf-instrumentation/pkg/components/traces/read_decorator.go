package traces

import (
	"context"
	"log/slog"
	"strconv"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/exec"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/traces/hostname"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

func rlog() *slog.Logger {
	return slog.With("component", "traces.ReadDecorator")
}

// InstanceIDConfig configures how Beyla will get the Instance ID of the traces/metrics
// from the current hostname + the instrumented process PID
type InstanceIDConfig struct {
	// HostnameDNSResolution is true if Beyla uses the DNS to resolve the local hostname or
	// false if it uses the local hostname.
	HostnameDNSResolution bool `yaml:"dns" env:"OTEL_EBPF_HOSTNAME_DNS_RESOLUTION"`
	// OverrideHostname can be optionally set to avoid resolving any hostname and using this
	// value. Beyla will anyway attach the process ID to the given hostname for composing
	// the instance ID.
	OverrideHostname string `yaml:"override_hostname" env:"OTEL_EBPF_HOSTNAME"`
}

// ReadDecorator is the input node of the processing graph. The eBPF tracers will send their
// traces to the ReadDecorator's TracesInput, and the ReadDecorator will decorate the traces with some
// basic information (e.g. instance ID) and forward them to the next pipeline stage
type ReadDecorator struct {
	TracesInput     *msg.Queue[[]request.Span]
	DecoratedTraces *msg.Queue[[]request.Span]

	InstanceID InstanceIDConfig
}

// decorator modifies a []request.Span slice to fill it with extra information that is not provided
// by the tracers (for example, the instance ID)
type decorator func(s *svc.Attrs, pid int)

func ReadFromChannel(r *ReadDecorator) swarm.InstanceFunc {
	decorate := hostNamePIDDecorator(&r.InstanceID)
	tracesInput := r.TracesInput.Subscribe()
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

func hostNamePIDDecorator(cfg *InstanceIDConfig) decorator {
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

func HostProcessEventDecoratorProvider(
	cfg *InstanceIDConfig,
	input, output *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		decorate := hostNamePIDDecorator(cfg)
		in := input.Subscribe()
		// if kubernetes decoration is disabled, we just bypass the node
		log := rlog().With("function", "HostProcessEventDecoratorProvider")
		return func(ctx context.Context) {
			defer output.Close()
			for {
				select {
				case pe, ok := <-in:
					if !ok {
						return
					}
					decorate(&pe.File.Service, int(pe.File.Pid))
					decorate(&pe.File.Service, int(pe.File.Pid))
					log.Debug("host decorating event", "event", pe, "ns", pe.File.Ns, "procPID", pe.File.Pid, "procPPID", pe.File.Ppid, "service", pe.File.Service.UID)
					output.Send(pe)
				case <-ctx.Done():
					log.Debug("context canceled. Exiting HostProcessEventDecorator")
					return
				}
			}
		}, nil
	}
}
