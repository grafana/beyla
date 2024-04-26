package export

import (
	"strconv"

	"github.com/grafana/beyla/pkg/internal/export/metric"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
)

func NamedGetters(internalName string) (metric.Getter[*ebpf.Record, string], bool) {
	var getter metric.Getter[*ebpf.Record, string]
	switch internalName {
	case "beyla.ip":
		getter = func(r *ebpf.Record) string { return r.Attrs.BeylaIP }
	case "transport":
		getter = func(r *ebpf.Record) string { return transport.Protocol(r.Id.TransportProtocol).String() }
	case "src.address":
		getter = func(r *ebpf.Record) string { return r.Id.SrcIP().IP().String() }
	case "dst.address":
		getter = func(r *ebpf.Record) string { return r.Id.DstIP().IP().String() }
	case "src.port":
		getter = func(r *ebpf.Record) string { return strconv.FormatUint(uint64(r.Id.SrcPort), 10) }
	case "dst.port":
		getter = func(r *ebpf.Record) string { return strconv.FormatUint(uint64(r.Id.DstPort), 10) }
	case "src.name":
		getter = func(r *ebpf.Record) string { return r.Attrs.SrcName }
	case "dst.name":
		getter = func(r *ebpf.Record) string { return r.Attrs.DstName }
	case "direction":
		getter = func(r *ebpf.Record) string { return directionStr(r.Id.Direction) }
	case "iface":
		getter = func(r *ebpf.Record) string { return r.Attrs.Interface }
	default:
		getter = func(r *ebpf.Record) string { return r.Attrs.Metadata[internalName] }
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
