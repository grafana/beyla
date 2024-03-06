package group

import (
	"fmt"
	"net"

	"github.com/yl2chen/cidranger"
)

const (
	unmatchedDrop = "drop"
	unmatchedPass = "pass"
)

type Group struct {
	CIDR      []string
	Unmatched string
}

type ipGrouper struct {
	ranger cidranger.Ranger
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
