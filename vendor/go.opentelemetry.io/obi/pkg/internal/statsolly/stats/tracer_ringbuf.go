// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stats // import "go.opentelemetry.io/obi/pkg/internal/statsolly/stats"

import (
	"context"
	"fmt"
	"log/slog"

	ciliumebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/internal/statsolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "stat.RingBufTracer")
}

// RingBufTracer reads stat events from an eBPF ring buffer, batches them, and
// forwards batches to the pipeline using the shared ForwardRingbuf infrastructure.
type RingBufTracer struct {
	statsMap *ciliumebpf.Map
	cfg      *config.EBPFTracer
}

func NewRingBufTracer(statsMap *ciliumebpf.Map, cfg *config.EBPFTracer) *RingBufTracer {
	return &RingBufTracer{
		statsMap: statsMap,
		cfg:      cfg,
	}
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[[]*ebpf.Stat]) swarm.RunFunc {
	forward := ebpfcommon.ForwardRingbuf(
		m.cfg,
		m.statsMap,
		parseStat,
		nil, // filter: no batch-level filtering
		rtlog(),
		nil, // metrics
	)
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		forward(ctx, out)
	}
}

func parseStat(record *ringbuf.Record) (*ebpf.Stat, bool, error) {
	stat, err := handleStatEvent(record)
	if err != nil {
		return nil, false, err
	}
	return &stat, false, nil
}

func handleStatEvent(record *ringbuf.Record) (ebpf.Stat, error) {
	eventType := ebpf.StatType(record.RawSample[0])
	switch eventType {
	case ebpf.StatTypeTCPRtt:
		return readTCPRttIntoStat(record)
	default:
		return ebpf.Stat{}, fmt.Errorf("unknown stats event [type %d]", uint8(eventType))
	}
}

func readTCPRttIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRtt](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}

	var srcAddr, dstAddr pipe.IPAddr
	var destinationPort uint16
	if event.Conn.S_port != 0 || event.Conn.D_port != 0 {
		srcAddr = pipe.IPAddr(event.Conn.S_addr)
		dstAddr = pipe.IPAddr(event.Conn.D_addr)
		destinationPort = event.Conn.D_port
	}

	sourcePort := event.Conn.S_port
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: event.SrttUs,
		},
		CommonAttrs: pipe.CommonAttrs{
			SrcAddr: srcAddr,
			DstAddr: dstAddr,
			SrcPort: sourcePort,
			DstPort: destinationPort,
		},
	}, nil
}
