package flow

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/rdns/ebpf/xdp"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/rdns/store"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

const (
	ReverseDNSNone        = "none"
	ReverseDNSLocalLookup = "local"
	ReverseDNSEBPF        = "ebpf"
)

func rdlog() *slog.Logger {
	return slog.With("component", "flow.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

// ReverseDNS is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall Beyla performance.
type ReverseDNS struct {
	// Type of ReverseDNS. Values are "none" (default), "local" and "ebpf"
	//nolint:undoc
	Type string `yaml:"type" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE"`

	// CacheLen only applies to the "local" ReverseDNS type. It
	// specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	//nolint:undoc
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN"`

	// CacheTTL only applies to the "local" ReverseDNS type. It
	// specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	//nolint:undoc
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL"`
}

func (r ReverseDNS) Enabled() bool {
	rdType := strings.ToLower(r.Type)
	return rdType == ReverseDNSLocalLookup || rdType == ReverseDNSEBPF
}

func ReverseDNSProvider(cfg *ReverseDNS, input, output *msg.Queue[[]*ebpf.Record]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}

		if err := checkEBPFReverseDNS(ctx, cfg); err != nil {
			return nil, err
		}
		// TODO: replace by a cache with fuzzy expiration time to avoid cache stampede
		cache := expirable.NewLRU[ebpf.IPAddr, string](cfg.CacheLen, nil, cfg.CacheTTL)

		log := rdlog()
		in := input.Subscribe()
		return func(_ context.Context) {
			defer output.Close()
			log.Debug("starting reverse DNS node")
			for flows := range in {
				for _, flow := range flows {
					if flow.Attrs.SrcName == "" {
						flow.Attrs.SrcName = optGetName(log, cache, flow.Id.SrcIp.In6U.U6Addr8)
					}
					if flow.Attrs.DstName == "" {
						flow.Attrs.DstName = optGetName(log, cache, flow.Id.DstIp.In6U.U6Addr8)
					}
				}
				output.Send(flows)
			}
		}, nil
	}
}

// changes reverse DNS method according to the provided configuration
func checkEBPFReverseDNS(ctx context.Context, cfg *ReverseDNS) error {
	if cfg.Type == ReverseDNSEBPF {
		// overriding netLookupAddr by an eBPF-based alternative
		ipToHosts := store.NewInMemory()
		if err := xdp.StartDNSPacketInspector(ctx, ipToHosts); err != nil {
			return fmt.Errorf("starting eBPF-based reverse DNS: %w", err)
		}
		netLookupAddr = ipToHosts.GetHostnames
	}
	return nil
}

func optGetName(log *slog.Logger, cache *expirable.LRU[ebpf.IPAddr, string], ip ebpf.IPAddr) string {
	if host, ok := cache.Get(ip); ok {
		return host
	}
	ipStr := ip.IP().String()
	if names, err := netLookupAddr(ipStr); err == nil && len(names) > 0 {
		cache.Add(ip, names[0])
		return names[0]
	} else if err != nil {
		log.Debug("error trying to lookup by IP address", "ip", ipStr, "error", err)
	}
	// return empty string. In a later pipeline stage it will be decorated with
	// the actual IP
	return ""
}
