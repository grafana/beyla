// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package transport // import "go.opentelemetry.io/obi/pkg/internal/netolly/flow/transport"

import (
	"fmt"
	"strconv"
	"strings"
)

// NetworkType value stores the L3 network protocol (IPv4, IPV6....)
// Values are defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
type NetworkType uint16

const (
	IPv4 = NetworkType(0x800)
	IPv6 = NetworkType(0x86DD)
)

// String representation of the Protocol enum
func (p NetworkType) String() string {
	switch p {
	case IPv4:
		return "ipv4"
	case IPv6:
		return "ipv6"
	}
	return strconv.Itoa(int(p))
}

// ParseNetworkType returns the NetworkType enum from the provided string
func ParseNetworkType(str string) (NetworkType, error) {
	switch strings.ToLower(str) {
	case "ipv4":
		return IPv4, nil
	case "ipv6":
		return IPv6, nil
	}
	return 0, fmt.Errorf("unknown protocol %q", str)
}
