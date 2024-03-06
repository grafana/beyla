package group

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/yl2chen/cidranger"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const (
	attrSrcCIDR = "src.cidr"
	attrDstCIDR = "dst.cidr"
)

func glog() *slog.Logger {
	return slog.With("component", "group.Group")
}

type Group struct {
	// CIDR list to decorate the "src.cidr" and "dst.cidr" from the source and destination
	// IP addresses.
	// If an IP matches multiple CIDR definitions, the flow will be decorated with the
	// narrowest CIDR. By this reason, you can safely add a 0.0.0.0/0 entry to group there
	// all the traffic that does not match any of the other CIDRs.
	CIDR []string `yaml:"cidr" env:"BEYLA_NETWORK_GROUP_CIDR" envSeparator:","`
}

func (g *Group) Enabled() bool {
	return len(g.CIDR) > 0
}

type ipGrouper struct {
	ranger cidranger.Ranger
}

func GrouperProvider(g Group) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	grouper, err := newIPGrouper(&g)
	if err != nil {
		return nil, fmt.Errorf("instantiating IP grouper: %w", err)
	}
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		glog().Debug("starting Grouper node")
		for flows := range in {
			for _, flow := range flows {
				grouper.decorate(flow)
			}
			out <- flows
		}
		glog().Debug("stopping Grouper node")
	}, nil
}

type customRangerEntry struct {
	ipNet net.IPNet
	cidr  string
}

func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func newIPGrouper(cfg *Group) (ipGrouper, error) {
	g := ipGrouper{ranger: cidranger.NewPCTrieRanger()}
	for _, cidr := range cfg.CIDR {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return g, fmt.Errorf("parsing CIDR %s: %w", cidr, err)
		}
		if err := g.ranger.Insert(&customRangerEntry{ipNet: *ipNet, cidr: cidr}); err != nil {
			return g, fmt.Errorf("inserting CIDR %s: %w", cidr, err)
		}
	}
	return g, nil
}

func (g *ipGrouper) CIDR(ip net.IP) string {
	entries, _ := g.ranger.ContainingNetworks(ip)
	if len(entries) == 0 {
		return ""
	}
	// will always return the lower-range CIDR
	return entries[len(entries)-1].(*customRangerEntry).cidr
}

func (g *ipGrouper) decorate(flow *ebpf.Record) {
	if flow.Attrs.Metadata == nil {
		flow.Attrs.Metadata = map[string]string{}
	}
	if srcCIDR := g.CIDR(flow.Id.SrcIP().IP()); srcCIDR != "" {
		flow.Attrs.Metadata[attrSrcCIDR] = srcCIDR
	}
	if dstCIDR := g.CIDR(flow.Id.DstIP().IP()); dstCIDR != "" {
		flow.Attrs.Metadata[attrDstCIDR] = dstCIDR
	}
}
