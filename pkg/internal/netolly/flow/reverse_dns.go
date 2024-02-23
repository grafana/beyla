package flow

import (
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const (
	ReverseDNSNone        = "none"
	ReverseDNSLocalLookup = "local"
	// añadir como opcion un dns externo como aqui https://github.com/hakluke/hakrevdns/blob/master/main.go
)

func rdlog() *slog.Logger {
	return slog.With("component", "flow.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

type ReverseDNS struct {
	// Type of ReverseDNS. Values are "none" (default) and "local".
	Type string `yaml:"type" env:"BEYLA_NETWORK_REVERSE_DNS_TYPE"`
	// CacheLen specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	CacheLen int `yaml:"cache_len" env:"BEYLA_NETWORK_REVERSE_DNS_CACHE_LEN"`
	// CacheTTL specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	CacheTTL time.Duration `yaml:"cache_expiry" env:"BEYLA_NETWORK_REVERSE_DNS_CACHE_TTL"`
}

func (r ReverseDNS) Enabled() bool {
	return r.Type == ReverseDNSLocalLookup
}

func ReverseDNSProvider(cfg ReverseDNS) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	// TODO: replace by a cache with fuzzy expiration time to avoid cache stampede
	cache := expirable.NewLRU[ebpf.IPAddr, string](cfg.CacheLen, nil, cfg.CacheTTL)

	log := rdlog()
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
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
			out <- flows
		}
	}, nil
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
