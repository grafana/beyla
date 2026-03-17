// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package netip // import "go.opentelemetry.io/obi/pkg/netip"

import (
	"fmt"
	"net"
	"strings"
)

// dependencies that can be injected from testing
var (
	interfaceByName = net.InterfaceByName
	interfaceAddrs  = net.InterfaceAddrs
	dial            = net.Dial
	ifaceAddrs      = func(iface *net.Interface) ([]net.Addr, error) {
		return iface.Addrs()
	}
)

// FetchAgentIP guesses the non-loopback IP address of the Agent host, according to the
// user-provided configuration:
//   - If agentIP is provided, this value is used whatever is the real IP of the Agent.
//   - agentIPIface specifies which interface this function should look into in order to pickup an address.
//   - agentIPType specifies which type of IP address should the agent pickup ("any" to pickup whichever
//     ipv4 or ipv6 address is found first)
func FetchAgentIP(agentIP string, agentIPIface string, agentIPType string) (net.IP, error) {
	if agentIP != "" {
		if ip := net.ParseIP(agentIP); ip != nil {
			return ip, nil
		}
		return nil, fmt.Errorf("can't parse provided IP %v", agentIP)
	}

	if agentIPType != IPTypeAny &&
		agentIPType != IPTypeIPV6 &&
		agentIPType != IPTypeIPV4 {
		return nil, fmt.Errorf("invalid IP type %q. Valid values are: %s, %s or %s",
			agentIPType, IPTypeIPV4, IPTypeIPV6, IPTypeAny)
	}

	switch agentIPIface {
	case IPIfaceLocal:
		return fromLocal(agentIPType)
	case IPIfaceExternal:
		return fromExternal(agentIPType)
	default:
		if !strings.HasPrefix(agentIPIface, IPIfaceNamedPrefix) {
			return nil, fmt.Errorf(
				"invalid IP interface %q. Valid values are: %s, %s or %s<iface_name>",
				agentIPIface, IPIfaceLocal, IPIfaceExternal, IPIfaceNamedPrefix)
		}
		return fromInterface(agentIPIface[len(IPIfaceNamedPrefix):], agentIPType)
	}
}

func fromInterface(ifName, ipType string) (net.IP, error) {
	iface, err := interfaceByName(ifName)
	if err != nil {
		return nil, err
	}
	addrs, err := ifaceAddrs(iface)
	if err != nil {
		return nil, err
	}
	if ip, ok := findAddress(addrs, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching %q addresses found at interface %v", ipType, ifName)
}

func fromLocal(ipType string) (net.IP, error) {
	addrs, err := interfaceAddrs()
	if err != nil {
		return nil, err
	}
	if ip, ok := findAddress(addrs, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching local %q addresses found", ipType)
}

func fromExternal(ipType string) (net.IP, error) {
	// We don't really care about the existence or nonexistence of the addresses.
	// This will just establish an external dialer where we can pickup the external
	// host address
	addrStr := "8.8.8.8:80"
	if ipType == IPTypeIPV6 {
		addrStr = "[2001:4860:4860::8888]:80"
	}
	conn, err := dial("udp", addrStr)
	if err != nil {
		return nil, fmt.Errorf("can't establish an external connection %w", err)
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); !ok {
		return nil, fmt.Errorf("unexpected local address type %T for external connection",
			conn.LocalAddr())
	} else if ip, ok := getIP(addr.IP, ipType); ok {
		return ip, nil
	}
	return nil, fmt.Errorf("no matching %q external addresses found", ipType)
}

func findAddress(addrs []net.Addr, ipType string) (net.IP, bool) {
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet != nil {
			if ip, ok := getIP(ipnet.IP, ipType); ok {
				return ip, true
			}
		}
	}
	return nil, false
}

func getIP(pip net.IP, ipType string) (net.IP, bool) {
	if pip == nil || pip.IsLoopback() {
		return nil, false
	}
	switch ipType {
	case IPTypeIPV4:
		if ip := pip.To4(); ip != nil {
			return ip, true
		}
	case IPTypeIPV6:
		// as any IP4 address can be converted to IP6, we only return any
		// address that can be converted to IP6 but not to IP4
		if ip := pip.To16(); ip != nil && pip.To4() == nil {
			return ip, true
		}
	default: // Any
		if ip := pip.To4(); ip != nil {
			return ip, true
		}
		if ip := pip.To16(); ip != nil {
			return ip, true
		}
	}
	return nil, false
}
