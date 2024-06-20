package ebpf

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
)

// RecordGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
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
	case attr.Direction:
		getter = func(r *Record) attribute.KeyValue {
			return attribute.String(string(attr.Direction), directionStr(r.Metrics.Direction))
		}
	case attr.Iface:
		getter = func(r *Record) attribute.KeyValue { return attribute.String(string(attr.Iface), r.Attrs.Interface) }
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

func directionStr(direction uint8) string {
	switch direction {
	case DirectionIngress:
		return "ingress"
	case DirectionEgress:
		return "egress"
	default:
		return ""
	}
}
