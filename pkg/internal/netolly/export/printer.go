package export

import (
	"fmt"
	"strings"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

type FlowPrinterEnabled bool

func (fpe FlowPrinterEnabled) Enabled() bool {
	return bool(fpe)
}

func FlowPrinterProvider(_ FlowPrinterEnabled) (node.TerminalFunc[[]*ebpf.Record], error) {
	return func(in <-chan []*ebpf.Record) {
		for flows := range in {
			for _, flow := range flows {
				printFlow(flow)
			}
		}
	}, nil
}

func printFlow(f *ebpf.Record) {
	sb := strings.Builder{}
	sb.WriteString("beyla.ip=")
	sb.WriteString(f.Attrs.BeylaIP)
	sb.WriteString(" iface=")
	sb.WriteString(f.Attrs.Interface)
	sb.WriteString(" direction=")
	sb.WriteString(fmt.Sprint(f.Id.Direction))
	sb.WriteString(" src.address=")
	sb.WriteString(f.Id.SrcIP().IP().String())
	sb.WriteString(" dst.address=")
	sb.WriteString(f.Id.DstIP().IP().String())
	sb.WriteString(" src.name=")
	sb.WriteString(f.Attrs.SrcName)
	sb.WriteString(" src.namespace=")
	sb.WriteString(f.Attrs.SrcNamespace)
	sb.WriteString(" dst.name=")
	sb.WriteString(f.Attrs.DstName)
	sb.WriteString(" dst.namespace=")
	sb.WriteString(f.Attrs.DstNamespace)

	for k, v := range f.Attrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(k)
		sb.WriteString("=")
		sb.WriteString(v)
	}

	fmt.Println("network_flow:", sb.String())
}
