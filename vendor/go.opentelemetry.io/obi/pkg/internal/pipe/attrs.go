// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pipe // import "go.opentelemetry.io/obi/pkg/internal/pipe"

import (
	"encoding/binary"
	"net"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

type CommonAttrs struct {
	SrcPort int
	DstPort int

	SrcAddr IPAddr
	DstAddr IPAddr
	// SrcName and DstName might be set from several sources along the processing/decoration pipeline:
	// - K8s entity
	// - Host name
	// - IP
	SrcName string
	DstName string

	// SrcZone and DstZone represent the Cloud availability zones of the source and destination
	SrcZone string
	DstZone string

	// OBIIP provides information about the source of the flow (the Agent that traced it)
	OBIIP    string
	Metadata map[attr.Name]string
}

// IP returns the net.IP equivalent object
func (ia *IPAddr) IP() net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise it would just encode the
// last 4 bytes of an IPv6 address
func (ia *IPAddr) IntEncodeV4() uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + ia.IP().String() + `"`), nil
}
