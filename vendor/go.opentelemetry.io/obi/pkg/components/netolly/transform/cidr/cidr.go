// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/yl2chen/cidranger"

	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
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

type CIDRDecorator struct {
	grouper ipGrouper
	enabled bool
}

func (d *CIDRDecorator) Decorate(r *ebpf.Record) {
	if !d.enabled {
		return
	}

	d.grouper.decorate(r)
}

func NewCIDRDecorator(g Definitions) (*CIDRDecorator, error) {
	d := &CIDRDecorator{
		enabled: g.Enabled(),
	}

	if !d.enabled {
		return d, nil
	}

	var err error
	d.grouper, err = newIPGrouper(g)
	if err != nil {
		return nil, fmt.Errorf("instantiating IP grouper: %w", err)
	}

	return d, nil
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
	if srcCIDR := g.CIDR(flow.SrcIP().IP()); srcCIDR != "" {
		flow.Attrs.Src.CIDR = srcCIDR
	}
	if dstCIDR := g.CIDR(flow.DstIP().IP()); dstCIDR != "" {
		flow.Attrs.Dst.CIDR = dstCIDR
	}
}
