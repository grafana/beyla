package export

import (
	"strconv"

	"github.com/grafana/beyla/pkg/internal/export/metric"
	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
)

func NamedGetters(name attr.Name) (metric.Getter[*ebpf.Record, string], bool) {
	var getter metric.Getter[*ebpf.Record, string]
	switch name {
	case attr.BeylaIP:
		getter = func(r *ebpf.Record) string { return r.Attrs.BeylaIP }
	case attr.Transport:
		getter = func(r *ebpf.Record) string { return transport.Protocol(r.Id.TransportProtocol).String() }
	case attr.SrcAddress:
		getter = func(r *ebpf.Record) string { return r.Id.SrcIP().IP().String() }
	case attr.DstAddres:
		getter = func(r *ebpf.Record) string { return r.Id.DstIP().IP().String() }
	case attr.SrcPort:
		getter = func(r *ebpf.Record) string { return strconv.FormatUint(uint64(r.Id.SrcPort), 10) }
	case attr.DstPort:
		getter = func(r *ebpf.Record) string { return strconv.FormatUint(uint64(r.Id.DstPort), 10) }
	case attr.SrcName:
		getter = func(r *ebpf.Record) string { return r.Attrs.SrcName }
	case attr.DstName:
		getter = func(r *ebpf.Record) string { return r.Attrs.DstName }
	case attr.Direction:
		getter = func(r *ebpf.Record) string { return directionStr(r.Id.Direction) }
	case attr.Iface:
		getter = func(r *ebpf.Record) string { return r.Attrs.Interface }
	default:
		getter = func(r *ebpf.Record) string { return r.Attrs.Metadata[name] }
	}
	return getter, getter != nil
}

func directionStr(direction uint8) string {
	switch direction {
	case ebpf.DirectionIngress:
		return "ingress"
	case ebpf.DirectionEgress:
		return "egress"
	default:
		return ""
	}
}
