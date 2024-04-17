package export

import (
	"strconv"
	"strings"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

// Attribute stores how to expose a metric attribute: its exposed name and how to
// get its value from the ebpf.Record.
type Attribute struct {
	Name string
	Get  func(r *ebpf.Record) string
}

// BuildPromAttributeGetters builds a list of Attribute getters for the names provided by the
// user configuration, ready to be passed to a Prometheus exporter.
// It differentiates two name formats: the exposed name for the attribute (uses _ for word separation, as
// required by Prometheus); and the internal name of the attribute (uses . for word separation, as internally Beyla
// stores the metadata).
// Whatever is the format provided by the user (dot-based or underscore-based), it converts dots to underscores
// and vice-versa to make sure that the correct format is used either internally or externally.
func BuildPromAttributeGetters(names []string) []Attribute {
	attrs := make([]Attribute, 0, len(names))
	for _, name := range names {
		exposedName := strings.ReplaceAll(name, ".", "_")
		internalName := strings.ReplaceAll(name, "_", ".")
		attrs = append(attrs, attributeFor(exposedName, internalName))
	}
	return attrs
}

// BuildOTELAttributeGetters builds a list of Attribute getters for the names provided by the
// user configuration, ready to be passed to an OpenTelemetry exporter.
// Whatever is the format of the user-provided attribute names (dot-based or underscore-based),
// it converts underscores to dots to make sure that the correct attribute name is exposed.
func BuildOTELAttributeGetters(names []string) []Attribute {
	attrs := make([]Attribute, 0, len(names))
	for _, name := range names {
		dotName := strings.ReplaceAll(name, "_", ".")
		attrs = append(attrs, attributeFor(dotName, dotName))
	}
	return attrs
}

func attributeFor(exposedName, internalName string) Attribute {
	var getter func(r *ebpf.Record) string
	switch internalName {
	case "beyla.ip":
		getter = func(r *ebpf.Record) string { return r.Attrs.BeylaIP }
	case "transport":
		getter = func(r *ebpf.Record) string { return l4TransportStr(r.Id.TransportProtocol) }
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
	return Attribute{Name: exposedName, Get: getter}
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

// values taken from the list of "Standard well-defined IP protocols" from uapi/linux/in.h
// nolint:cyclop
func l4TransportStr(proto uint8) string {
	switch proto {
	case 0:
		return "IP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 4:
		return "IPIP"
	case 6:
		return "TCP"
	case 8:
		return "EGP"
	case 12:
		return "PUP"
	case 17:
		return "UDP"
	case 22:
		return "IDP"
	case 29:
		return "TP"
	case 33:
		return "DCCP"
	case 41:
		return "IPV6"
	case 46:
		return "RSVP"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	case 92:
		return "MTP"
	case 94:
		return "BEETPH"
	case 98:
		return "ENCAP"
	case 103:
		return "PIM"
	case 108:
		return "COMP"
	case 115:
		return "L2TP"
	case 132:
		return "SCTP"
	case 136:
		return "UDPLITE"
	case 137:
		return "MPLS"
	case 143:
		return "ETHERNET"
	case 255:
		return "RAW"
		// TODO: consider adding an extra byte to TransportProtocol to support this protocol
		// case 262:
		//   return "MPTCP"
	}
	return strconv.Itoa(int(proto))
}
