package transform

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/app/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/helpers/maps"
	kube2 "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/kube"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

const (
	ResolverDNS = maps.Bits(1 << iota)
	ResolverK8s
)

func resolverSources(str []string) maps.Bits {
	return maps.MappedBits(str, map[string]maps.Bits{
		"dns":        ResolverDNS,
		"k8s":        ResolverK8s,
		"kube":       ResolverK8s,
		"kubernetes": ResolverK8s,
	}, maps.WithTransform(strings.ToLower))
}

type NameResolverConfig struct {
	// Sources for name resolving. Accepted values: dns, k8s
	//nolint:undoc
	Sources []string `yaml:"sources" env:"OTEL_EBPF_NAME_RESOLVER_SOURCES" envSeparator:"," envDefault:"k8s"`
	// CacheLen specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	//nolint:undoc
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_NAME_RESOLVER_CACHE_LEN"`
	// CacheTTL specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	//nolint:undoc
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_NAME_RESOLVER_CACHE_TTL"`
}

type NameResolver struct {
	cache *expirable.LRU[string, string]
	cfg   *NameResolverConfig
	db    *kube2.Store

	sources maps.Bits
}

func NameResolutionProvider(ctxInfo *global.ContextInfo, cfg *NameResolverConfig,
	input, output *msg.Queue[[]request.Span],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if cfg == nil || len(cfg.Sources) == 0 {
			// if no sources are configured, we just bypass the node
			return swarm.Bypass(input, output)
		}
		return nameResolver(ctx, ctxInfo, cfg, input, output)
	}
}

func nameResolver(ctx context.Context, ctxInfo *global.ContextInfo, cfg *NameResolverConfig,
	input, output *msg.Queue[[]request.Span],
) (swarm.RunFunc, error) {
	sources := resolverSources(cfg.Sources)

	var kubeStore *kube2.Store
	if ctxInfo.K8sInformer.IsKubeEnabled() {
		var err error
		kubeStore, err = ctxInfo.K8sInformer.Get(ctx)
		if err != nil {
			return nil, fmt.Errorf("initializing NameResolutionProvider: %w", err)
		}
	} else {
		sources &= ^ResolverK8s
	}
	// after potentially remove k8s resolver, check again if
	// this node needs to be bypassed
	if sources == 0 {
		return swarm.Bypass(input, output)
	}

	nr := NameResolver{
		cfg:     cfg,
		db:      kubeStore,
		cache:   expirable.NewLRU[string, string](cfg.CacheLen, nil, cfg.CacheTTL),
		sources: sources,
	}

	in := input.Subscribe()
	return func(_ context.Context) {
		// output channel must be closed so later stages in the pipeline can finish in cascade
		defer output.Close()

		for spans := range in {
			for i := range spans {
				s := &spans[i]
				nr.resolveNames(s)
			}
			output.Send(spans)
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
	var hn, pn, ns string
	if span.IsClientSpan() {
		hn, span.OtherNamespace = nr.resolve(&span.Service, span.Host)
		pn, ns = nr.resolve(&span.Service, span.Peer)
	} else {
		pn, span.OtherNamespace = nr.resolve(&span.Service, span.Peer)
		hn, ns = nr.resolve(&span.Service, span.Host)
	}
	if span.Service.UID.Namespace == "" && ns != "" {
		span.Service.UID.Namespace = ns
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

func (nr *NameResolver) resolve(svc *svc.Attrs, ip string) (string, string) {
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

func (nr *NameResolver) cleanName(svc *svc.Attrs, ip, n string) string {
	n = strings.TrimSuffix(n, ".")
	n = trimSuffixIgnoreCase(n, ".svc.cluster.local")
	n = trimSuffixIgnoreCase(n, "."+svc.UID.Namespace)

	kubeNamespace, ok := svc.Metadata[attr.K8sNamespaceName]
	if ok && kubeNamespace != "" && kubeNamespace != svc.UID.Namespace {
		n = trimSuffixIgnoreCase(n, "."+kubeNamespace)
	}

	dashIP := strings.ReplaceAll(ip, ".", "-") + "."
	n = trimPrefixIgnoreCase(n, dashIP)

	return n
}

func (nr *NameResolver) dnsResolve(svc *svc.Attrs, ip string) (string, string) {
	if ip == "" {
		return "", ""
	}

	if nr.sources.Has(ResolverK8s) && nr.db != nil {
		ipAddr := net.ParseIP(ip)

		if ipAddr != nil && !ipAddr.IsLoopback() {
			n, ns := nr.resolveFromK8s(ip)

			if n != "" {
				return n, ns
			}
		}
	}

	if nr.sources.Has(ResolverDNS) {
		n := nr.resolveIP(ip)
		if n == ip {
			return n, svc.UID.Namespace
		}
		n = nr.cleanName(svc, ip, n)
		return n, svc.UID.Namespace
	}
	return "", ""
}

func (nr *NameResolver) resolveFromK8s(ip string) (string, string) {
	return nr.db.ServiceNameNamespaceForIP(ip)
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
