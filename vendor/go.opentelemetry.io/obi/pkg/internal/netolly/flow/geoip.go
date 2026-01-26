// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/oschwald/maxminddb-golang"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// GeoIP is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall Beyla performance.
type GeoIP struct {
	IPInfo      IPInfoConfig  `yaml:"ipinfo"`
	MaxMindInfo MaxMindConfig `yaml:"maxmind"`
	CacheLen    int           `yaml:"cache_len" env:"OTEL_EBPF_NETWORK_GEOIP_CACHE_LEN" validate:"gte=0"`
	CacheTTL    time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_NETWORK_GEOIP_CACHE_TTL" validate:"gte=0"`
}

type IPInfoConfig struct {
	Path string `yaml:"path" env:"OTEL_EBPF_NETWORK_GEOIP_IPINFO_PATH"`
}
type MaxMindConfig struct {
	CountryPath string `yaml:"country_path" env:"OTEL_EBPF_NETWORK_GEOIP_MAXMIND_COUNTRY_PATH"`
	ASNPath     string `yaml:"asn_path" env:"OTEL_EBPF_NETWORK_GEOIP_MAXMIND_ASN_PATH"`
}

type ipInfo struct {
	Country string
	ASN     string
}

func (g GeoIP) Enabled() bool {
	return g.IPInfo.Path != "" || (g.MaxMindInfo.ASNPath != "" && g.MaxMindInfo.CountryPath != "")
}

func geoiplog() *slog.Logger {
	return slog.With("component", "flow.GeoIP")
}

func GeoIPProvider(cfg *GeoIP, input, output *msg.Queue[[]*ebpf.Record]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}
		lookupFn, err := getLookupFn(cfg)
		if err != nil {
			return nil, err
		}

		log := geoiplog()
		in := input.Subscribe(msg.SubscriberName("flow.GeoIP"))
		cache := expirable.NewLRU[ebpf.IPAddr, ipInfo](cfg.CacheLen, nil, cfg.CacheTTL)
		cachedLookup := func(addr *ebpf.IPAddr) (ipInfo, error) {
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
			for flows := range in {
				for _, flow := range flows {
					srcInfo, err := cachedLookup(flow.Id.SrcIP())
					if err != nil {
						failureLogFn("failed to perform geoip lookup for source", "err", err)
					}
					dstInfo, err := cachedLookup(flow.Id.DstIP())
					if err != nil {
						failureLogFn("failed to perform geoip lookup for destination", "err", err)
					}
					if flow.Attrs.Metadata == nil {
						flow.Attrs.Metadata = map[attr.Name]string{}
					}
					flow.Attrs.Metadata[attr.SrcCountry] = srcInfo.Country
					flow.Attrs.Metadata[attr.DstCountry] = dstInfo.Country
					flow.Attrs.Metadata[attr.SrcASN] = srcInfo.ASN
					flow.Attrs.Metadata[attr.DstASN] = dstInfo.ASN
				}
				output.Send(flows)
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
		record := ipInfoLiteRecord{}
		err := db.Lookup(addr, &record)
		if err != nil {
			return ipInfo{}, fmt.Errorf("looking up address: %w", err)
		}
		return ipInfo(record), nil
	}, nil
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
		countryRecord := maxmindCountryRecord{}
		if err := countryDB.Lookup(addr, &countryRecord); err != nil {
			return ipInfo{}, fmt.Errorf("looking up country for address: %w", err)
		}
		asnRecord := maxmindASNRecord{}
		if err := asnDB.Lookup(addr, &asnRecord); err != nil {
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
