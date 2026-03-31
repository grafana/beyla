// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns // import "go.opentelemetry.io/obi/pkg/internal/pipe/rdns"

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/rdns/ebpf/xdp"
	"go.opentelemetry.io/obi/pkg/internal/rdns/store"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

const (
	ReverseDNSNone        = "none"
	ReverseDNSLocalLookup = "local"
	ReverseDNSEBPF        = "ebpf"
)

func rdlog() *slog.Logger {
	return slog.With("component", "rdns.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

// ReverseDNS is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall OBI performance.
type ReverseDNS struct {
	// Type of ReverseDNS. Values are "none" (default), "local" and "ebpf"
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE for backwards-compatibility
	Type string `yaml:"type" env:"OTEL_EBPF_REVERSE_DNS_TYPE,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE}" validate:"oneof=none local ebpf" jsonschema:"type=string,enum=none,enum=local,enum=ebpf"`

	// CacheLen only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN for backwards-compatibility
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_REVERSE_DNS_CACHE_LEN,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN}" validate:"gte=0"`

	// CacheTTL only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	// It also accepts OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL for backwards-compatibility
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_REVERSE_DNS_CACHE_TTL,expand" envDefault:"${OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL}" validate:"gte=0"`
}

func (r ReverseDNS) Enabled() bool {
	rdType := strings.ToLower(r.Type)
	return rdType == ReverseDNSLocalLookup || rdType == ReverseDNSEBPF
}

func ReverseDNSProvider[T any](cfg *ReverseDNS, attrs func(T) *pipe.CommonAttrs, ebpfCfg *config.EBPFTracer, input, output *msg.Queue[[]T]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}

		if err := checkEBPFReverseDNS(ctx, cfg, ebpfCfg); err != nil {
			return nil, err
		}
		// TODO: replace by a cache with fuzzy expiration time to avoid cache stampede
		cache := expirable.NewLRU[pipe.IPAddr, string](cfg.CacheLen, nil, cfg.CacheTTL)

		log := rdlog()
		in := input.Subscribe(msg.SubscriberName("rdns.ReverseDNS"))
		return func(_ context.Context) {
			defer output.Close()
			log.Debug("starting reverse DNS node")
			for items := range in {
				for _, item := range items {
					a := attrs(item)
					if a.SrcName == "" {
						a.SrcName = optGetName(log, cache, a.SrcAddr)
					}
					if a.DstName == "" {
						a.DstName = optGetName(log, cache, a.DstAddr)
					}
				}
				output.Send(items)
			}
		}, nil
	}
}

// changes reverse DNS method according to the provided configuration
func checkEBPFReverseDNS(ctx context.Context, cfg *ReverseDNS, ebpfCfg *config.EBPFTracer) error {
	if cfg.Type == ReverseDNSEBPF {
		// overriding netLookupAddr by an eBPF-based alternative
		dnsCache, err := store.NewInMemory(cfg.CacheLen)
		if err != nil {
			return fmt.Errorf("initializing eBPF-based reverse DNS cache: %w", err)
		}
		if err := xdp.StartDNSPacketInspector(ctx, dnsCache, ebpfCfg); err != nil {
			return fmt.Errorf("starting eBPF-based reverse DNS: %w", err)
		}
		netLookupAddr = dnsCache.GetHostnames
	}
	return nil
}

func optGetName(log *slog.Logger, cache *expirable.LRU[pipe.IPAddr, string], ip pipe.IPAddr) string {
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
