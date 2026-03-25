// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr // import "go.opentelemetry.io/obi/pkg/internal/pipe/cidr"

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/yl2chen/cidranger"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
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

func DecoratorProvider[T any](g Definitions, attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !g.Enabled() {
			return swarm.Bypass(input, output)
		}
		grouper, err := newIPGrouper(g)
		if err != nil {
			return nil, fmt.Errorf("instantiating IP grouper: %w", err)
		}
		in := input.Subscribe(msg.SubscriberName("cidr.Decorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, glog().Debug, func(items []T) {
				for _, item := range items {
					grouper.decorate(attrs(item))
				}
				output.Send(items)
			})
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

func (g *ipGrouper) decorate(a *pipe.CommonAttrs) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	if srcCIDR := g.CIDR(a.SrcAddr[:]); srcCIDR != "" {
		a.Metadata[attr.SrcCIDR] = srcCIDR
	}
	if dstCIDR := g.CIDR(a.DstAddr[:]); dstCIDR != "" {
		a.Metadata[attr.DstCIDR] = dstCIDR
	}
}
