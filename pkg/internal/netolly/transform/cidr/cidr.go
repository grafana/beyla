package cidr

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/mariomac/pipes/pipe"
	"github.com/yl2chen/cidranger"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

const (
	attrSrcCIDR = "src.cidr"
	attrDstCIDR = "dst.cidr"
)

func glog() *slog.Logger {
	return slog.With("component", "cidr.Decorator")
}

// Definitions contains a list of CIDRs to be set as the "src.cidr" and "dst.cidr"
// attribute as a function of the source and destination IP addresses.
type Definitions []string

func (c Definitions) Enabled() bool {
	return len(c) > 0
}

type ipGrouper struct {
	ranger cidranger.Ranger
}

func DecoratorProvider(g Definitions) (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	if !g.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just bypassing it.
		return pipe.Bypass[[]*ebpf.Record](), nil
	}
	grouper, err := newIPGrouper(g)
	if err != nil {
		return nil, fmt.Errorf("instantiating IP grouper: %w", err)
	}
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		glog().Debug("starting node")
		for flows := range in {
			for _, flow := range flows {
				grouper.decorate(flow)
			}
			out <- flows
		}
		glog().Debug("stopping node")
	}, nil
}

type customRangerEntry struct {
	ipNet net.IPNet
	cidr  string
}

func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func newIPGrouper(cfg Definitions) (ipGrouper, error) {
	g := ipGrouper{ranger: cidranger.NewPCTrieRanger()}
	for _, cidr := range cfg {
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
	// will always return the narrower matching CIDR
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
