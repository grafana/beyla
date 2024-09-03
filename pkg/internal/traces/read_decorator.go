package traces

import (
	"context"
	"log/slog"
	"strconv"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/traces/hostname"
)

const defaultIDCacheLen = 128

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

	// Undocumented properties aimed at fine-grained tuning

	// InternalIDCacheLen will need to be increased if the number of instrumented processes by
	// a single instance is larger than defaultIDCacheLen
	InternalIDCacheLen int `yaml:"internal_cache_len" env:"BEYLA_INSTANCE_ID_INTERNAL_CACHE_LEN"`
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

func ReadFromChannel(ctx context.Context, r *ReadDecorator) pipe.StartFunc[[]request.Span] {
	decorate := hostNamePIDDecorator(&r.InstanceID)
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
	}
}

func hostNamePIDDecorator(cfg *InstanceIDConfig) decorator {
	// TODO: periodically update in case the current Beyla instance is created from a VM snapshot running as a different hostname
	resolver := hostname.CreateResolver(cfg.OverrideHostname, "", cfg.HostnameDNSResolution)
	fullHostName, _, err := resolver.Query()
	log := rlog().With("function", "instance_ID_hostNamePIDDecorator")
	if err != nil {
		log.Warn("can't read hostname. Leaving empty. Consider overriding"+
			" the BEYLA_HOSTNAME property", "error", err)
	} else {
		log.Info("using hostname", "hostname", fullHostName)
	}

	// caching instance ID composition for speed and saving memory generation
	cacheLen := defaultIDCacheLen
	if cfg.InternalIDCacheLen != 0 {
		cacheLen = cfg.InternalIDCacheLen
	}
	uidsCache, _ := lru.New[uint32, svc.UID](cacheLen)

	return func(spans []request.Span) {
		for i := range spans {
			uid, ok := uidsCache.Get(spans[i].Pid.HostPID)
			if !ok {
				uid = svc.UID(fullHostName + "-" + strconv.Itoa(int(spans[i].Pid.HostPID)))
				uidsCache.Add(spans[i].Pid.HostPID, uid)
			}
			spans[i].ServiceID.UID = uid
			spans[i].ServiceID.HostName = fullHostName
		}
	}
}
