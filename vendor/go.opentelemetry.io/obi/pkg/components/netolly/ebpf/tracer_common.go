// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

const (
	// DirectionUnset is a convenience value to specify an unset/removed direction field
	DirectionUnset = 0xFF
	// DirectionIngress and DirectionEgress values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
	DirectionIngress = 0
	DirectionEgress  = 1

	InterfaceUnset = 0xFFFFFFFF
)
