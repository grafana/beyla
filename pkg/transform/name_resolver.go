package transform

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/mariomac/pipes/pkg/node"
)

type NameResolverConfig struct {
	// CacheLen specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	CacheLen int `yaml:"cache_len" env:"BEYLA_NAME_RESOLVER_CACHE_LEN"`
	// CacheTTL specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	CacheTTL time.Duration `yaml:"cache_expiry" env:"BEYLA_NAME_RESOLVER_CACHE_TTL"`
}

type NameResolver struct {
	cache    *expirable.LRU[string, string]
	fqnCache *expirable.LRU[string, string]
	cfg      *NameResolverConfig
}

func NameResolutionProvider(cfg *NameResolverConfig) (node.MiddleFunc[[]request.Span, []request.Span], error) {
	nr := NameResolver{
		cfg:      cfg,
		cache:    expirable.NewLRU[string, string](cfg.CacheLen, nil, cfg.CacheTTL),
		fqnCache: expirable.NewLRU[string, string](cfg.CacheLen, nil, cfg.CacheTTL),
	}

	return func(in <-chan []request.Span, out chan<- []request.Span) {
		for spans := range in {
			for i := range spans {
				s := &spans[i]
				nr.resolveNames(s)
			}
			out <- spans
		}
	}, nil
}

func trimSuffixIgnoreCase(s, suffix string) string {
	if len(s) >= len(suffix) && strings.EqualFold(s[len(s)-len(suffix):], suffix) {
		return s[:len(s)-len(suffix)]
	}
	return s
}

func trimPrefixIgnoreCase(s, prefix string) string {
	if len(s) >= len(prefix) && strings.EqualFold(s[0:len(prefix)], prefix) {
		return s[len(prefix):]
	}
	return s
}

func (nr *NameResolver) resolveNames(span *request.Span) {
	var peer string
	var ok bool
	if len(span.Peer) > 0 {
		peer, ok = nr.fqnCache.Get(span.Peer)
		if ok {
			span.PeerName = peer
		} else {
			peer = nr.resolve(&span.ServiceID, span.Peer)
			if len(peer) > 0 {
				span.PeerName = peer
			} else {
				span.PeerName = span.Peer
			}
		}
	}

	if len(span.Host) > 0 {
		host, ok := nr.fqnCache.Get(span.Host)
		if ok {
			span.HostName = host
		} else {
			host = nr.resolve(&span.ServiceID, span.Host)
			if len(host) > 0 {
				_, ok := span.ServiceID.Metadata[kube.PodName]
				if ok && strings.EqualFold(host, peer) && span.ServiceID.AutoName {
					span.HostName = span.ServiceID.Name
				} else {
					span.HostName = host
				}
			} else {
				span.HostName = span.Host
			}
			nr.fqnCache.Add(span.Host, span.HostName)
		}
	}
}

func (nr *NameResolver) resolve(svc *svc.ID, ip string) string {
	if ip == "" {
		return ""
	}
	n := nr.resolveIP(ip)
	if n == ip {
		return n
	}

	n = strings.TrimSuffix(n, ".")
	n = trimSuffixIgnoreCase(n, ".svc.cluster.local")
	n = trimSuffixIgnoreCase(n, "."+svc.Namespace)

	kubeNamespace, ok := svc.Metadata[kube.NamespaceName]
	if ok && kubeNamespace != "" && kubeNamespace != svc.Namespace {
		n = trimSuffixIgnoreCase(n, "."+kubeNamespace)
	}

	dashIP := strings.ReplaceAll(ip, ".", "-") + "."
	n = trimPrefixIgnoreCase(n, dashIP)

	//fmt.Printf("%s -> %s\n", ip, n)

	return n
}

func (nr *NameResolver) resolveIP(ip string) string {
	if host, ok := nr.cache.Get(ip); ok {
		return host
	}

	var r *net.Resolver
	addr, err := r.LookupAddr(context.Background(), ip)

	if err != nil {
		nr.cache.Add(ip, ip)
		return ip
	}

	for _, a := range addr {
		nr.cache.Add(ip, a)
		return a
	}

	nr.cache.Add(ip, ip)
	return ip
}
