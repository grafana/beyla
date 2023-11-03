package traces

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/traces/hostname"
)

func rlog() *slog.Logger {
	return slog.With("component", "traces.ReadDecorator")
}

// InstanceIDConfig configures how Beyla will get the Instance ID of the traces/metrics
// from the current hostname + the instrumented process PID
type InstanceIDConfig struct {
	// HostnameDNSResolution is true if Beyla uses the DNS to resolve the local hostname or
	// false if it uses the local hostname.
	HostnameDNSResolution bool `yaml:"dns" env:"BEYLA_HOSTNAME_DNS_RESOLUTION"`
	// OverrideHostname can be optionally set to avoid resolving any hostname and using this
	// value. Beyla will anyway attach the process ID to the given hostname for composing
	// the instance ID.
	OverrideHostname string `yaml:"override_hostname" env:"BEYLA_HOSTNAME"`
	// OverrideInstanceID can be optionally set to avoid Beyla composing the instance ID
	// and use this value. If you are managing multiple processes from a single Beyla instance,
	// all the processes will have the same Instance ID.
	OverrideInstanceID string `yaml:"override_instance_id" env:"BEYLA_INSTANCE_ID"`
}

// ReadDecorator is the input node of the processing graph. The eBPF tracers will send their
// traces to the ReadDecorator's TracesInput, and the ReadDecorator will decorate the traces with some
// basic information (e.g. instance ID) and forward them to the next pipeline stage
type ReadDecorator struct {
	TracesInput <-chan []request.Span

	InstanceID InstanceIDConfig
}

// decorator modifies a []request.Span slice to fill it with extra information that is not provided
// by the tracers (for example, the instance ID)
type decorator func(spans []request.Span)

func ReadFromChannel(ctx context.Context, r ReadDecorator) (node.StartFunc[[]request.Span], error) {
	decorate := getDecorator(&r.InstanceID)
	return func(out chan<- []request.Span) {
		cancelChan := ctx.Done()
		for {
			select {
			case trace, ok := <-r.TracesInput:
				if ok {
					decorate(trace)
					out <- trace
				} else {
					rlog().Debug("input channel closed. Exiting traces input loop")
					return
				}
			case <-cancelChan:
				rlog().Debug("context canceled. Exiting traces input loop")
				return
			}
		}
	}, nil
}

func getDecorator(cfg *InstanceIDConfig) decorator {
	if cfg.OverrideInstanceID != "" {
		return func(spans []request.Span) {
			for i := range spans {
				spans[i].ServiceID.Instance = cfg.OverrideInstanceID
			}
		}
	}
	return hostNamePIDDecorator(cfg)
}

func hostNamePIDDecorator(cfg *InstanceIDConfig) decorator {
	// TODO: periodically update in case the current Beyla instance is created from a VM snapshot running as a different hostname
	resolver := hostname.CreateResolver(cfg.OverrideHostname, "", cfg.HostnameDNSResolution)
	fullHostName, _, err := resolver.Query()
	log := rlog().With("function", "instance_ID_hostNamePIDDecorator")
	if err != nil {
		log.Warn("can't read hostname. Leaving empty. Consider overriding"+
			" the BEYLA_HOSTNAME or BEYLA_INSTANCE_ID properties",
			"error", err)
	} else {
		log.Info("using hostname", "hostname", fullHostName)
	}

	return func(spans []request.Span) {
		for i := range spans {
			// TODO: if this has a performance impact or generates too much unnecessary memory, use an LRU cache
			spans[i].ServiceID.Instance = fmt.Sprintf("%s-%d", fullHostName, spans[i].Pid.HostPID)
		}
	}
}
