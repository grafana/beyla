// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package export // import "go.opentelemetry.io/obi/pkg/internal/statsolly/export"

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func StatPrinterProvider(enabled bool, input *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	if !enabled {
		// just return a no-op
		return func(_ context.Context) {}
	}

	in := input.Subscribe(msg.SubscriberName("StatPrinter"))
	return func(_ context.Context) {
		for stats := range in {
			for _, stat := range stats {
				printStat(stat)
			}
		}
	}
}

func printStat(s *ebpf.Stat) {
	sb := strings.Builder{}
	sb.WriteString("ip=")
	sb.WriteString(s.CommonAttrs.OBIIP)
	sb.WriteString(" src.address=")
	sb.WriteString(s.CommonAttrs.SrcAddr.IP().String())
	sb.WriteString(" dst.address=")
	sb.WriteString(s.CommonAttrs.DstAddr.IP().String())
	sb.WriteString(" src.name=")
	sb.WriteString(s.CommonAttrs.SrcName)
	sb.WriteString(" dst.name=")
	sb.WriteString(s.CommonAttrs.DstName)
	sb.WriteString(" src.port=")
	sb.WriteString(strconv.FormatUint(uint64(s.CommonAttrs.SrcPort), 10))
	sb.WriteString(" dst.port=")
	sb.WriteString(strconv.FormatUint(uint64(s.CommonAttrs.DstPort), 10))

	for k, v := range s.CommonAttrs.Metadata {
		sb.WriteString(" ")
		sb.WriteString(string(k))
		sb.WriteString("=")
		sb.WriteString(v)
	}
	if s.Type == ebpf.StatTypeTCPRtt {
		sb.WriteString(" srtt=")
		sb.WriteString(strconv.FormatFloat(float64(s.TCPRtt.SrttUs), 'f', -1, 64))
	}
	fmt.Println("stats:", sb.String())
}
