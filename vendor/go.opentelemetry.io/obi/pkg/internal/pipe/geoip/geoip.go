// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package geoip // import "go.opentelemetry.io/obi/pkg/internal/pipe/geoip"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/oschwald/maxminddb-golang/v2"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// GeoIP is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall OBI performance.
type GeoIP struct {
	IPInfo      IPInfoConfig  `yaml:"ipinfo"`
	MaxMindInfo MaxMindConfig `yaml:"maxmind"`
	// It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_LEN for backwards-compatibility
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_GEOIP_CACHE_LEN,expand" envDefault:"${OTEL_EBPF_NETWORK_GEOIP_CACHE_LEN}" validate:"gte=0"`
	// It also accepts OTEL_EBPF_NETWORK_GEOIP_CACHE_TTL for backwards-compatibility
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_GEOIP_CACHE_TTL,expand" envDefault:"${OTEL_EBPF_NETWORK_GEOIP_CACHE_TTL}" validate:"gte=0"`
}

type IPInfoConfig struct {
	// It also accepts OTEL_EBPF_NETWORK_GEOIP_IPINFO_PATH for backwards-compatibility
	Path string `yaml:"path" env:"OTEL_EBPF_GEOIP_IPINFO_PATH,expand" envDefault:"${OTEL_EBPF_NETWORK_GEOIP_IPINFO_PATH}"`
}
type MaxMindConfig struct {
	// It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_COUNTRY_PATH for backwards-compatibility
	CountryPath string `yaml:"country_path" env:"OTEL_EBPF_GEOIP_MAXMIND_COUNTRY_PATH,expand" envDefault:"${OTEL_EBPF_NETWORK_GEOIP_MAXMIND_COUNTRY_PATH}"`
	// It also accepts OTEL_EBPF_NETWORK_GEOIP_MAXMIND_ASN_PATH for backwards-compatibility
	ASNPath string `yaml:"asn_path" env:"OTEL_EBPF_GEOIP_MAXMIND_ASN_PATH,expand" envDefault:"${OTEL_EBPF_NETWORK_GEOIP_MAXMIND_ASN_PATH}"`
}

type ipInfo struct {
	Country string
	ASN     string
}

func (g GeoIP) Enabled() bool {
	return g.IPInfo.Path != "" || (g.MaxMindInfo.ASNPath != "" && g.MaxMindInfo.CountryPath != "")
}

func geoiplog() *slog.Logger {
	return slog.With("component", "pipe.GeoIP")
}

func GeoIPProvider[T any](cfg *GeoIP, attrs func(T) *pipe.CommonAttrs, input, output *msg.Queue[[]T]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}
		lookupFn, err := getLookupFn(cfg)
		if err != nil {
			return nil, err
		}

		log := geoiplog()
		in := input.Subscribe(msg.SubscriberName("pipe.GeoIP"))
		cache := expirable.NewLRU[pipe.IPAddr, ipInfo](cfg.CacheLen, nil, cfg.CacheTTL)
		cachedLookup := func(addr *pipe.IPAddr) (ipInfo, error) {
			info, ok := cache.Get(*addr)
			if ok {
				return info, nil
			}
			info, err := lookupFn(addr.IP())
			if err != nil {
				return info, err
			}
			cache.Add(*addr, info)
			return info, nil
		}

		// only warn the first time to prevent log flooding
		var failureLogFn func(string, ...any)
		failureLogFn = func(msg string, args ...any) {
			log.Warn(msg, args...)
			failureLogFn = log.Debug
		}

		return func(_ context.Context) {
			defer output.Close()
			log.Debug("starting GeoIP node")
			for items := range in {
				for _, item := range items {
					a := attrs(item)
					srcInfo, err := cachedLookup(&a.SrcAddr)
					if err != nil {
						failureLogFn("failed to perform geoip lookup for source", "err", err)
					}
					dstInfo, err := cachedLookup(&a.DstAddr)
					if err != nil {
						failureLogFn("failed to perform geoip lookup for destination", "err", err)
					}
					if a.Metadata == nil {
						a.Metadata = map[attr.Name]string{}
					}
					a.Metadata[attr.SrcCountry] = srcInfo.Country
					a.Metadata[attr.DstCountry] = dstInfo.Country
					a.Metadata[attr.SrcASN] = srcInfo.ASN
					a.Metadata[attr.DstASN] = dstInfo.ASN
				}
				output.Send(items)
			}
		}, nil
	}
}

type IPLookupFn func(addr net.IP) (ipInfo, error)

func getLookupFn(cfg *GeoIP) (IPLookupFn, error) {
	if cfg.IPInfo.Path != "" {
		return ipinfoLookup(cfg.IPInfo.Path)
	}
	if cfg.MaxMindInfo.ASNPath != "" && cfg.MaxMindInfo.CountryPath != "" {
		return maxmindlookup(cfg.MaxMindInfo.CountryPath, cfg.MaxMindInfo.ASNPath)
	}
	return nil, errors.New("no provider configured")
}

type ipInfoLiteRecord struct {
	Country string `maxminddb:"country_code"`
	ASN     string `maxminddb:"asn"`
}

func ipinfoLookup(path string) (IPLookupFn, error) {
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening ipinfo database: %w", err)
	}
	return func(addr net.IP) (ipInfo, error) {
		netAddr, ok := netipAddrFromNetIP(addr)
		if !ok {
			return ipInfo{}, fmt.Errorf("invalid IP address: %v", addr)
		}
		record := ipInfoLiteRecord{}
		if err := db.Lookup(netAddr).Decode(&record); err != nil {
			return ipInfo{}, fmt.Errorf("looking up address: %w", err)
		}
		return ipInfo(record), nil
	}, nil
}

func netipAddrFromNetIP(addr net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(addr)
	if !ok {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

type maxmindCountryRecord struct {
	Country struct {
		Code string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}
type maxmindASNRecord struct {
	ASN uint64 `maxminddb:"autonomous_system_number"`
}

func maxmindlookup(countryPath, asnPath string) (IPLookupFn, error) {
	countryDB, err := maxminddb.Open(countryPath)
	if err != nil {
		return nil, fmt.Errorf("opening maxmind country database: %w", err)
	}
	asnDB, err := maxminddb.Open(asnPath)
	if err != nil {
		return nil, fmt.Errorf("opening maxmind country database: %w", err)
	}
	return func(addr net.IP) (ipInfo, error) {
		netAddr, ok := netipAddrFromNetIP(addr)
		if !ok {
			return ipInfo{}, fmt.Errorf("invalid IP address: %v", addr)
		}
		countryRecord := maxmindCountryRecord{}
		if err := countryDB.Lookup(netAddr).Decode(&countryRecord); err != nil {
			return ipInfo{}, fmt.Errorf("looking up country for address: %w", err)
		}
		asnRecord := maxmindASNRecord{}
		if err := asnDB.Lookup(netAddr).Decode(&asnRecord); err != nil {
			return ipInfo{}, fmt.Errorf("looking up country for address: %w", err)
		}
		out := ipInfo{
			Country: countryRecord.Country.Code,
		}
		if asnRecord.ASN != 0 {
			out.ASN = fmt.Sprintf("AS%d", asnRecord.ASN)
		}
		return out, nil
	}, nil
}
