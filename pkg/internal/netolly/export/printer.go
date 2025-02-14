package export

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
)

func FlowPrinterProvider(enabled bool) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !enabled {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
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
	sb.WriteString("transport=")
	sb.WriteString(strconv.Itoa(int(f.Id.TransportProtocol)))
	sb.WriteString(" beyla.ip=")
	sb.WriteString(f.Attrs.BeylaIP)
	sb.WriteString(" iface=")
	sb.WriteString(f.Attrs.Interface)
	sb.WriteString(" iface_direction=")
	sb.WriteString(strconv.Itoa(int(f.Metrics.IfaceDirection)))
	sb.WriteString(" src.address=")
	sb.WriteString(f.Id.SrcIP().IP().String())
	sb.WriteString(" dst.address=")
	sb.WriteString(f.Id.DstIP().IP().String())
	sb.WriteString(" src.name=")
	sb.WriteString(f.Attrs.SrcName)
	sb.WriteString(" dst.name=")
	sb.WriteString(f.Attrs.DstName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.Id.SrcPort), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.Id.DstPort), 10))

	for k, v := range f.Attrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(string(k))
		sb.WriteString("=")
		sb.WriteString(v)
	}

	fmt.Println("network_flow:", sb.String())
}
