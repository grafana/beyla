// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/netolly/flow/transport"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
)

const (
	DirectionRequest  = "request"
	DirectionResponse = "response"
	DirectionUnknown  = "unknown"
)

type RecordGettersConfig struct {
	PortGuessPolicy flowdef.PortGuessPolicy
}

// RecordGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func RecordGetters(cfg RecordGettersConfig) attributes.NamedGetters[*Record, attribute.KeyValue] {
	return recordGetters{cfg: cfg}.get
}

type recordGetters struct {
	cfg RecordGettersConfig
}

func (r recordGetters) get(name attr.Name) (attributes.Getter[*Record, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Record, attribute.KeyValue]
	switch name {
	case attr.OBIIP:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.OBIIP), r.CommonAttrs.OBIIP) }
	case attr.Transport:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Transport), transport.Protocol(r.NetAttrs.TransportProtocol).String())
		}
	case attr.NetworkType:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.NetworkType), transport.NetworkType(r.NetAttrs.EthProtocol).String())
		}
	case attr.NetworkProtocol:
		guesser := r.cfg.serverPortGuesser()
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.NetworkProtocol),
				transport.ApplicationPortToString(serverPort(r, guesser)))
		}
	case attr.SrcAddress:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcAddress), r.CommonAttrs.SrcAddr.IP().String())
		}
	case attr.DstAddress:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstAddress), r.CommonAttrs.DstAddr.IP().String())
		}
	case attr.SrcPort:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.Int(string(attr.SrcPort), int(r.CommonAttrs.SrcPort))
		}
	case attr.DstPort:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.Int(string(attr.DstPort), int(r.CommonAttrs.DstPort))
		}
	case attr.SrcName:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcName), r.CommonAttrs.SrcName)
		}
	case attr.DstName:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstName), r.CommonAttrs.DstName)
		}
	case attr.IfaceDirection:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.IfaceDirection), ifaceDirectionStr(r.Metrics.IfaceDirection))
		}
	case attr.Iface:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Iface), r.NetAttrs.Interface)
		}
	case attr.ClientPort:
		guesser := r.cfg.clientPortGuesser()
		getter = func(r *Record) attribute.KeyValue {
			return attribute.Int(string(attr.ClientPort), int(clientPort(r, guesser)))
		}
	case attr.Direction:
		guesser := r.cfg.clientPortGuesser()
		getter = func(r *Record) attribute.KeyValue {
			var direction string
			switch r.Metrics.Initiator {
			case InitiatorDst:
				direction = DirectionResponse
			case InitiatorSrc:
				direction = DirectionRequest
			default:
				// guess client port
				clientPort := guesser(r)
				switch clientPort {
				case 0:
					direction = DirectionUnknown
				case r.CommonAttrs.SrcPort:
					direction = DirectionRequest
				default:
					direction = DirectionResponse
				}
			}
			return attribute.String(string(attr.Direction), direction)
		}
	case attr.ServerPort:
		guesser := r.cfg.serverPortGuesser()
		getter = func(r *Record) attribute.KeyValue {
			return attribute.Int(string(attr.ServerPort), int(serverPort(r, guesser)))
		}
	case attr.SrcZone:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.SrcZone), r.CommonAttrs.SrcZone)
		}
	case attr.DstZone:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.DstZone), r.CommonAttrs.DstZone)
		}
	default:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(name), r.CommonAttrs.Metadata[name])
		}
	}
	return getter, getter != nil
}

func RecordStringGetters(
	rgc RecordGettersConfig,
) attributes.NamedGetters[*Record, string] {
	otelGetters := RecordGetters(rgc)
	return func(name attr.Name) (attributes.Getter[*Record, string], bool) {
		if g, ok := otelGetters(name); ok {
			return func(r *Record) string { return g(r).Value.Emit() }, true
		}
		return nil, false
	}
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
