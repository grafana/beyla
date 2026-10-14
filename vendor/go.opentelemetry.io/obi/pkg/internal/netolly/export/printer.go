// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/internal/netolly/export"

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func FlowPrinterProvider(enabled bool, input *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	if !enabled {
		// just return a no-op
		return func(_ context.Context) {}
	}

	in := input.Subscribe(msg.SubscriberName("FlowPrinter"))
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
	sb.WriteString(strconv.Itoa(int(f.NetAttrs.TransportProtocol)))
	sb.WriteByte(' ')
	sb.WriteString(attr.VendorPrefix)
	sb.WriteString(".ip=")
	sb.WriteString(f.CommonAttrs.OBIIP)
	sb.WriteString(" iface=")
	sb.WriteString(f.NetAttrs.Interface)
	sb.WriteString(" iface_direction=")
	sb.WriteString(strconv.Itoa(int(f.Metrics.IfaceDirection)))
	sb.WriteString(" src.address=")
	sb.WriteString(f.CommonAttrs.SrcAddr.IP().String())
	sb.WriteString(" dst.address=")
	sb.WriteString(f.CommonAttrs.DstAddr.IP().String())
	sb.WriteString(" src.name=")
	sb.WriteString(f.CommonAttrs.SrcName)
	sb.WriteString(" dst.name=")
	sb.WriteString(f.CommonAttrs.DstName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.CommonAttrs.SrcPort), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(f.CommonAttrs.DstPort), 10))

	for k, v := range f.CommonAttrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(string(k))
		sb.WriteString("=")
		sb.WriteString(v)
	}

	fmt.Println("network_flow:", sb.String())
}
