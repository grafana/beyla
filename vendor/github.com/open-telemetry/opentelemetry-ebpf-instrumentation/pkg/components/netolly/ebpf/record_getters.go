package ebpf

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/flow/transport"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

const (
	DirectionRequest  = "request"
	DirectionResponse = "response"
)

// RecordGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
//
//nolint:cyclop
func RecordGetters(name attr.Name) (attributes.Getter[*Record, attribute.KeyValue], bool) {
	var getter attributes.Getter[*Record, attribute.KeyValue]
	switch name {
	case attr.BeylaIP:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.BeylaIP), r.Attrs.BeylaIP) }
	case attr.Transport:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Transport), transport.Protocol(r.Id.TransportProtocol).String())
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
			var serverPort uint16
			switch r.Metrics.Initiator {
			case InitiatorDst:
				serverPort = r.Id.SrcPort
			case InitiatorSrc:
				serverPort = r.Id.DstPort
			default:
				// guess it, assuming that ephemeral ports for clients would be usually higher
				serverPort = min(r.Id.DstPort, r.Id.SrcPort)
			}
			return attribute.Int(string(attr.ServerPort), int(serverPort))
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
