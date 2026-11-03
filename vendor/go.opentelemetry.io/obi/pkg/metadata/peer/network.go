// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
)

var privateBlocks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

type network struct {
	addresses []netip.Addr
	allowed   []netip.Prefix
}

func localNetwork(cidrs []string) (network, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return network{}, err
	}

	var addresses []netip.Addr
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return network{}, fmt.Errorf("reading interface %s: %w", iface.Name, err)
		}

		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil {
				addresses = append(addresses, prefix.Addr().Unmap())
			}
		}
	}

	return makeNetwork(addresses, cidrs)
}

func makeNetwork(addresses []netip.Addr, cidrs []string) (network, error) {
	n := network{addresses: addresses}

	if len(cidrs) > 0 {
		for _, cidr := range cidrs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return network{}, err
			}

			n.allowed = append(n.allowed, prefix.Masked())
		}

		return n, nil
	}

	for _, block := range privateBlocks {
		for _, addr := range addresses {
			if block.Contains(addr.Unmap()) {
				n.allowed = append(n.allowed, block)
				break
			}
		}
	}
	return n, nil
}

func (n network) isLocal(addr netip.Addr) bool {
	if addr.IsLoopback() {
		return true
	}

	return slices.Contains(n.addresses, addr)
}

func (n network) permits(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() {
		return false
	}

	for _, prefix := range n.allowed {
		if prefix.Contains(addr.Unmap()) {
			return true
		}
	}

	return false
}
