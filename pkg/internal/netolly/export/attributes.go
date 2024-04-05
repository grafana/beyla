package export

import (
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
		exposedName := strings.Replace(name, ".", "_", -1)
		internalName := strings.Replace(name, "_", ".", -1)
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
		dotName := strings.Replace(name, "_", ".", -1)
		attrs = append(attrs, attributeFor(dotName, dotName))
	}
	return attrs
}

func attributeFor(exposedName, internalName string) Attribute {
	var getter func(r *ebpf.Record) string
	switch internalName {
	case "beyla.ip":
		getter = func(r *ebpf.Record) string { return r.Attrs.BeylaIP }
	case "src.address":
		getter = func(r *ebpf.Record) string { return r.Id.SrcIP().IP().String() }
	case "dst.address":
		getter = func(r *ebpf.Record) string { return r.Id.DstIP().IP().String() }
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
