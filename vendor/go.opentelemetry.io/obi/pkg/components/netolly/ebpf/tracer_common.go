// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
)

const (
	// DirectionUnset is a convenience value to specify an unset/removed direction field
	DirectionUnset = 0xFF
	// DirectionIngress and DirectionEgress values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	DirectionIngress = 0
	DirectionEgress  = 1

	// InitiatorSrc and InitiatorDst values set accordingly to flows_common.h definition
	InitiatorSrc = 1
	InitiatorDst = 2

	InterfaceUnset = 0xFFFFFFFF
)

func parseProtocolList(list []string) ([]transport.Protocol, error) {
	if len(list) == 0 {
		return []transport.Protocol{}, nil
	}

	ret := make([]transport.Protocol, 0, len(list))

	for _, s := range list {
		p, err := transport.ParseProtocol(s)
		if err != nil {
			return nil, err
		}

		ret = append(ret, p)
	}

	return ret, nil
}

func assignProtocolList(m *ebpf.Map, list []transport.Protocol) error {
	for _, proto := range list {
		if err := m.Put(uint32(proto), uint8(1)); err != nil {
			return fmt.Errorf("error writing map: %w", err)
		}
	}

	return nil
}
