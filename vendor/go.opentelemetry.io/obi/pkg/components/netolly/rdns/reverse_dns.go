// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rdns

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/components/rdns/ebpf/xdp"
	"go.opentelemetry.io/obi/pkg/components/rdns/store"
)

type ReverseDNSMode uint8

const (
	ReverseDNSNone = ReverseDNSMode(iota)
	ReverseDNSLocalLookup
	ReverseDNSEBPF
)

func (m *ReverseDNSMode) UnmarshalText(text []byte) error {
	switch strings.ToLower(strings.TrimSpace(string(text))) {
	case "none":
		*m = ReverseDNSNone
		return nil
	case "local":
		*m = ReverseDNSLocalLookup
		return nil
	case "ebpf":
		*m = ReverseDNSEBPF
		return nil
	}

	return fmt.Errorf("invalid reverse DNS mode: '%s'", text)
}

func (m ReverseDNSMode) MarshalText() ([]byte, error) {
	switch m {
	case ReverseDNSNone:
		return []byte("none"), nil
	case ReverseDNSLocalLookup:
		return []byte("local"), nil
	case ReverseDNSEBPF:
		return []byte("ebpf"), nil
	}

	return nil, fmt.Errorf("invalid reverse DNS mode: %d", m)
}

func rdlog() *slog.Logger {
	return slog.With("component", "flow.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

// ReverseDNS is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall Beyla performance.
type ReverseDNS struct {
	// Type of ReverseDNS. Values are "none" (default), "local" and "ebpf"
	Type ReverseDNSMode `yaml:"type" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE"`

	// CacheLen only applies to the "local" ReverseDNS type. It
	// specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN"`

	// CacheTTL only applies to the "local" ReverseDNS type. It
	// specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL"`
}

func (r ReverseDNS) Enabled() bool {
	return r.Type == ReverseDNSLocalLookup || r.Type == ReverseDNSEBPF
}

type ReverseDNSFunc func(*ebpf.Record)

type ReverseDNSEnricher struct {
	cache   *expirable.LRU[ebpf.IPAddr, string]
	enabled bool
	log     *slog.Logger
}

func NewReverseDNSEnricher(ctx context.Context, cfg *ReverseDNS) (*ReverseDNSEnricher, error) {
	r := &ReverseDNSEnricher{
		enabled: cfg.Enabled(),
		log:     rdlog(),
	}

	if !r.enabled {
		return r, nil
	}

	if err := checkEBPFReverseDNS(ctx, cfg); err != nil {
		return nil, err
	}

	// TODO: replace by a cache with fuzzy expiration time to avoid cache stampede
	r.cache = expirable.NewLRU[ebpf.IPAddr, string](cfg.CacheLen, nil, cfg.CacheTTL)

	return r, nil
}

func (r *ReverseDNSEnricher) Enrich(flow *ebpf.Record) {
	if !r.enabled {
		return
	}

	if flow.Attrs.Src.TargetName == "" {
		flow.Attrs.Src.TargetName = optGetName(r.log, r.cache, *flow.SrcIP())
	}
	if flow.Attrs.Dst.TargetName == "" {
		flow.Attrs.Dst.TargetName = optGetName(r.log, r.cache, *flow.DstIP())
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
