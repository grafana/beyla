package export

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/netolly/ebpf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

func FlowPrinterProvider(enabled bool, input *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	if !enabled {
		// just return a no-op
		return func(_ context.Context) {}
	}

	in := input.Subscribe()
	return func(_ context.Context) {
		for flows := range in {
			for _, flow := range flows {
				printFlow(flow)
			}
		}
	}
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
