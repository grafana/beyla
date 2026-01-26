// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/netolly/flow/transport"
)

const (
	DirectionRequest  = "request"
	DirectionResponse = "response"
)

func serverPort(r *Record) uint16 {
	switch r.Metrics.Initiator {
	case InitiatorDst:
		return r.Id.SrcPort
	case InitiatorSrc:
		return r.Id.DstPort
	default:
		// guess it, assuming that ephemeral ports for clients would be usually higher
		return min(r.Id.DstPort, r.Id.SrcPort)
	}
}

// RecordGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func RecordGetters(name attr.Name) (attributes.Getter[*Record, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Record, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.OBIIP), r.Attrs.OBIIP) }
	case attr.Transport:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Transport), transport.Protocol(r.Id.TransportProtocol).String())
		}
	case attr.NetworkType:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.NetworkType), transport.NetworkType(r.Id.EthProtocol).String())
		}
	case attr.NetworkProtocol:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.NetworkProtocol), transport.ApplicationPortToString(serverPort(r)))
		}
	case attr.SrcAddress:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), r.Id.SrcIP().IP().String())
		}
	case attr.DstAddres:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstAddres), r.Id.DstIP().IP().String())
		}
	case attr.SrcPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.SrcPort), int(r.Id.SrcPort)) }
	case attr.DstPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.DstPort), int(r.Id.DstPort)) }
	case attr.SrcName:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.SrcName), r.Attrs.SrcName) }
	case attr.DstName:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.DstName), r.Attrs.DstName) }
	case attr.IfaceDirection:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.IfaceDirection), ifaceDirectionStr(r.Metrics.IfaceDirection))
		}
	case attr.Iface:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.Iface), r.Attrs.Interface) }
	case attr.ClientPort:
		getter = func(r *Record) attribute.KeyValue {
			var clientPort uint16
			switch r.Metrics.Initiator {
			case InitiatorDst:
				clientPort = r.Id.DstPort
			case InitiatorSrc:
				clientPort = r.Id.SrcPort
			default:
				// guess it, assuming that ephemeral ports for clients would be usually higher
				clientPort = max(r.Id.DstPort, r.Id.SrcPort)
			}
			return attribute.Int(string(attr.ClientPort), int(clientPort))
		}
	case attr.Direction:
		getter = func(r *Record) attribute.KeyValue {
			var direction string
			switch r.Metrics.Initiator {
			case InitiatorDst:
				direction = DirectionResponse
			case InitiatorSrc:
				direction = DirectionRequest
			default:
				// guess it, assuming that ephemeral ports for clients would be usually higher
				if r.Id.SrcPort > r.Id.DstPort {
					direction = DirectionRequest
				} else {
					direction = DirectionResponse
				}
			}
			return attribute.String(string(attr.Direction), direction)
		}
	case attr.ServerPort:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.Int(string(attr.ServerPort), int(serverPort(r)))
		}
	case attr.SrcZone:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.SrcZone), r.Attrs.SrcZone) }
	case attr.DstZone:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.DstZone), r.Attrs.DstZone) }
	default:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(name), r.Attrs.Metadata[name]) }
	}
	return getter, getter != nil
}

func RecordStringGetters(name attr.Name) (attributes.Getter[*Record, string], bool) {
	if g, ok := RecordGetters(name); ok {
		return func(r *Record) string { return g(r).Value.Emit() }, true
	}
	return nil, false
}

func ifaceDirectionStr(direction uint8) string {
	switch direction {
	case DirectionIngress:
		return "ingress"
	case DirectionEgress:
		return "egress"
	default:
		return ""
	}
}
