package ebpf

import (
	"strconv"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
)

// RecordGetters returns the attributes.Getter function that returns the string value of a given
// attribute name.
func RecordGetters(name attr.Name) (attributes.Getter[*Record, string], bool) {
	var getter attributes.Getter[*Record, string]
	switch name {
	case attr.BeylaIP:
		getter = func(r *Record) string { return r.Attrs.BeylaIP }
	case attr.Transport:
		getter = func(r *Record) string { return transport.Protocol(r.Id.TransportProtocol).String() }
	case attr.SrcAddress:
		getter = func(r *Record) string { return r.Id.SrcIP().IP().String() }
	case attr.DstAddres:
		getter = func(r *Record) string { return r.Id.DstIP().IP().String() }
	case attr.SrcPort:
		getter = func(r *Record) string { return strconv.FormatUint(uint64(r.Id.SrcPort), 10) }
	case attr.DstPort:
		getter = func(r *Record) string { return strconv.FormatUint(uint64(r.Id.DstPort), 10) }
	case attr.SrcName:
		getter = func(r *Record) string { return r.Attrs.SrcName }
	case attr.DstName:
		getter = func(r *Record) string { return r.Attrs.DstName }
	case attr.Direction:
		getter = func(r *Record) string { return directionStr(r.Id.Direction) }
	case attr.Iface:
		getter = func(r *Record) string { return r.Attrs.Interface }
	default:
		getter = func(r *Record) string { return r.Attrs.Metadata[name] }
	}
	return getter, getter != nil
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
