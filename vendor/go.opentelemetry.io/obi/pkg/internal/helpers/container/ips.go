// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package container // import "go.opentelemetry.io/obi/pkg/internal/helpers/container"

import (
	"fmt"
	"net"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/netns"
)

// injectable for testing
var (
	withNetNS       = netns.WithNetNS
	interfaceAddrs  = net.InterfaceAddrs
	isIsolatedNetNS = netns.IsIsolated
)

// IPsForPID returns the non-loopback IPv4/IPv6 addresses visible in pid's
// network namespace when that namespace is isolated from the agent and host
// (PID 1). This covers Docker/containerd bridge networking. Host-network and
// bare-host processes share those namespaces; their interface addresses are
// not process identity, so this returns no IPs.
func IPsForPID(pid app.PID) ([]string, error) {
	isolated, err := isIsolatedNetNS(int(pid))
	if err != nil {
		return nil, fmt.Errorf("checking netns isolation: %w", err)
	}
	if !isolated {
		return nil, nil
	}

	var ips []string
	err = withNetNS(int(pid), func() error {
		addrs, err := interfaceAddrs()
		if err != nil {
			return fmt.Errorf("listing interface addresses: %w", err)
		}
		ips = uniqueNonLoopbackIPs(addrs)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func uniqueNonLoopbackIPs(addrs []net.Addr) []string {
	seen := make(map[string]struct{}, len(addrs))
	var out []string
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet == nil || ipnet.IP == nil || ipnet.IP.IsLoopback() {
			continue
		}
		// Prefer the canonical string form (IPv4 as dotted quad, not :ffff:).
		ip := ipnet.IP
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		s := ip.String()
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
