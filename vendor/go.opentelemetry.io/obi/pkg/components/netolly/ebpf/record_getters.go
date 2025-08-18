// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/components/netolly/flow/transport"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	DirectionRequest  = "request"
	DirectionResponse = "response"
	DirectionUnknown  = "unknown"
)

func requestDirection(startDirection, ifaceDirection uint8) string {
	if startDirection == DirectionEgress {
		// this is a client call
		switch ifaceDirection {
		case DirectionEgress:
			return DirectionRequest
		case DirectionIngress:
			return DirectionResponse
		}
	} else if startDirection == DirectionIngress {
		// this is a server call
		switch ifaceDirection {
		case DirectionEgress:
			return DirectionResponse
		case DirectionIngress:
			return DirectionRequest
		}
	}

	return DirectionUnknown
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
	case attr.SrcAddress:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), r.SrcIP().IP().String())
		}
	case attr.DstAddres:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstAddres), r.DstIP().IP().String())
		}
	case attr.SrcPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.SrcPort), int(r.SrcPort())) }
	case attr.DstPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.DstPort), int(r.DstPort())) }
	case attr.SrcName:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcName), r.Attrs.Src.TargetName)
		}
	case attr.DstName:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstName), r.Attrs.Dst.TargetName)
		}
	case attr.IfaceDirection:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.IfaceDirection), ifaceDirectionStr(r.Metrics.IfaceDirection))
		}
	case attr.Iface:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.Iface), r.Attrs.Interface) }
	case attr.ClientPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.ClientPort), int(r.ClientPort())) }
	case attr.Direction:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Direction), requestDirection(r.Metrics.StartDirection, r.Metrics.IfaceDirection))
		}
	case attr.ServerPort:
		getter = func(r *Record) attribute.KeyValue { return attribute.Int(string(attr.ServerPort), int(r.ServerPort())) }
	case attr.SrcZone:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcZone), r.Attrs.Src.TargetZone)
		}
	case attr.DstZone:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstZone), r.Attrs.Dst.TargetZone)
		}
	default:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(name), "") }
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
