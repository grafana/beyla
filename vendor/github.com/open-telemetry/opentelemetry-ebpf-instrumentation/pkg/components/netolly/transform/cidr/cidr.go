package cidr

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/yl2chen/cidranger"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
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

func DecoratorProvider(g Definitions, input, output *msg.Queue[[]*ebpf.Record]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !g.Enabled() {
			return swarm.Bypass(input, output)
		}
		grouper, err := newIPGrouper(g)
		if err != nil {
			return nil, fmt.Errorf("instantiating IP grouper: %w", err)
		}
		in := input.Subscribe()
		return func(_ context.Context) {
			defer output.Close()
			glog().Debug("starting node")
			for flows := range in {
				for _, flow := range flows {
					grouper.decorate(flow)
				}
				output.Send(flows)
			}
			glog().Debug("stopping node")
		}, nil
	}
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
		flow.Attrs.Metadata = map[attr.Name]string{}
	}
	if srcCIDR := g.CIDR(flow.Id.SrcIP().IP()); srcCIDR != "" {
		flow.Attrs.Metadata[attr.SrcCIDR] = srcCIDR
	}
	if dstCIDR := g.CIDR(flow.Id.DstIP().IP()); dstCIDR != "" {
		flow.Attrs.Metadata[attr.DstCIDR] = dstCIDR
	}
}
