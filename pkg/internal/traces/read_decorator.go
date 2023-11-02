package traces

import (
	"context"
	"log/slog"
	"os"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/request"
)

func rlog() *slog.Logger {
	return slog.With("component", "traces.ReadDecorator")
}

// ReadDecorator is the input node of the processing graph. The eBPF tracers will send their
// traces to the ReadDecorator's TracesInput, and the ReadDecorator will decorate the traces with some
// basic information (e.g. instance ID) and forward them to the next pipeline stage
type ReadDecorator struct {
	TracesInput <-chan []request.Span

	OverrideHostname   string
	OverrideInstanceID string
}

// decorator modifies a request.Span to fill it with extra information that is not provided
// by the tracers (for example, the instance ID)
type decorator func(span *request.Span)

func ReadFromChannel(ctx context.Context, r ReadDecorator) (node.StartFunc[[]request.Span], error) {
	decorate := getDecorator(&r)
	return func(out chan<- []request.Span) {
		cancelChan := ctx.Done()
		for {
			select {
			case trace, ok := <-r.TracesInput:
				if ok {
					decorate(&trace)
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

func getDecorator(cfg *ReadDecorator) decorator {
	if cfg.OverrideInstanceID != "" {
		return func(span *request.Span) {
			span.InstanceID = cfg.OverrideInstanceID
		}
	}
	return hostNamePIDDecorator(cfg)
}

func hostNamePIDDecorator(cfg *ReadDecorator) decorator {
	log := rlog().With("function", "instance_ID_hostNamePIDDecorator")
	hostName := cfg.OverrideHostname
	if hostName == "" {
		var err error
		// Know issue: this scenario will fail with users that install and run Beyla as a host
		// process in a Virtual Machine (e.g. AWS instance) and then create a snapshot of that
		// virtual machine
		if hostName, err = os.Hostname(); err != nil {
			log.Warn("can't read hostname. Leaving empty. Consider overriding" +
				" the BEYLA_HOSTNAME or BEYLA_INSTANCE_ID properties",
				"error", err)
		}
	}

	return func(span *request.Span) {

	}
}
