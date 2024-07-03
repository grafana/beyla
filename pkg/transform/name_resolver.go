package transform

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/mariomac/pipes/pipe"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	kube2 "github.com/grafana/beyla/pkg/internal/transform/kube"
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
	cache *expirable.LRU[string, string]
	cfg   *NameResolverConfig
	db    *kube2.Database
}

func NameResolutionProvider(ctxInfo *global.ContextInfo, cfg *NameResolverConfig) pipe.MiddleProvider[[]request.Span, []request.Span] {
	return func() (pipe.MiddleFunc[[]request.Span, []request.Span], error) {
		if cfg == nil {
			return pipe.Bypass[[]request.Span](), nil
		}
		return nameResolver(ctxInfo, cfg)
	}
}

func nameResolver(ctxInfo *global.ContextInfo, cfg *NameResolverConfig) (pipe.MiddleFunc[[]request.Span, []request.Span], error) {
	nr := NameResolver{
		cfg:   cfg,
		db:    ctxInfo.AppO11y.K8sDatabase,
		cache: expirable.NewLRU[string, string](cfg.CacheLen, nil, cfg.CacheTTL),
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
	var hn, pn string
	if span.IsClientSpan() {
		hn, span.OtherNamespace = nr.resolve(&span.ServiceID, span.Host)
		pn, _ = nr.resolve(&span.ServiceID, span.Peer)
	} else {
		pn, span.OtherNamespace = nr.resolve(&span.ServiceID, span.Peer)
		hn, _ = nr.resolve(&span.ServiceID, span.Host)
	}
	// don't set names if the peer and host names have been already decorated
	// in a previous stage (e.g. Kubernetes decorator)
	if pn != "" {
		span.PeerName = pn
	}
	if hn != "" {
		span.HostName = hn
	}
}

func (nr *NameResolver) resolve(svc *svc.ID, ip string) (string, string) {
	var name, ns string

	if len(ip) > 0 {
		var peer string
		peer, ns = nr.dnsResolve(svc, ip)
		if len(peer) > 0 {
			name = peer
		} else {
			name = ip
		}
	}

	return name, ns
}

func (nr *NameResolver) cleanName(svc *svc.ID, ip, n string) string {
	n = strings.TrimSuffix(n, ".")
	n = trimSuffixIgnoreCase(n, ".svc.cluster.local")
	n = trimSuffixIgnoreCase(n, "."+svc.Namespace)

	kubeNamespace, ok := svc.Metadata[attr.K8sNamespaceName]
	if ok && kubeNamespace != "" && kubeNamespace != svc.Namespace {
		n = trimSuffixIgnoreCase(n, "."+kubeNamespace)
	}

	dashIP := strings.ReplaceAll(ip, ".", "-") + "."
	n = trimPrefixIgnoreCase(n, dashIP)

	return n
}

func (nr *NameResolver) dnsResolve(svc *svc.ID, ip string) (string, string) {
	if ip == "" {
		return "", ""
	}

	if nr.db != nil {
		ipAddr := net.ParseIP(ip)

		if ipAddr != nil && !ipAddr.IsLoopback() {
			n, ns := nr.resolveFromK8s(ip)

			if n != "" {
				return n, ns
			}
		}
	}

	n := nr.resolveIP(ip)
	if n == ip {
		return n, svc.Namespace
	}

	n = nr.cleanName(svc, ip, n)

	return n, svc.Namespace
}

func (nr *NameResolver) resolveFromK8s(ip string) (string, string) {
	svcInfo := nr.db.ServiceInfoForIP(ip)
	if svcInfo == nil {
		podInfo := nr.db.PodInfoForIP(ip)
		if podInfo == nil {
			return "", ""
		}
		return podInfo.ServiceName(), podInfo.Namespace
	}

	return svcInfo.Name, svcInfo.Namespace
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
