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
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
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
	case ebpf.StatTypeTCPFailedConnection:
		return readTCPFailedConnectionsIntoStat(record)
	case ebpf.StatTypeTCPRetransmit:
		return readTCPRetransmitIntoStat(record)
	case ebpf.StatTypeTCPIo:
		return readTCPIoIntoStat(record)
	default:
		return ebpf.Stat{}, fmt.Errorf("unknown stats event [type %d]", uint8(eventType))
	}
}

func connToCommonAttrs(conn ebpf.Conn) pipe.CommonAttrs {
	if conn.S_port == 0 && conn.D_port == 0 {
		return pipe.CommonAttrs{}
	}
	return pipe.CommonAttrs{
		SrcAddr: pipe.IPAddr(conn.S_addr),
		DstAddr: pipe.IPAddr(conn.D_addr),
		SrcPort: conn.S_port,
		DstPort: conn.D_port,
	}
}

func readTCPRttIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRtt](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPRtt,
		TCPRtt: &ebpf.TCPRtt{
			SrttUs: event.SrttUs,
			Role:   event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
	}, nil
}

func readTCPFailedConnectionsIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPFailedConnection](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPFailedConnection,
		TCPFailedConnection: &ebpf.TCPFailedConnection{
			Reason: event.Reason,
			Role:   event.Role,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
	}, nil
}

func readTCPRetransmitIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPRetransmit](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	return ebpf.Stat{
		Type:          ebpf.StatTypeTCPRetransmit,
		TCPRetransmit: true,
		CommonAttrs:   connToCommonAttrs(event.Conn),
	}, nil
}

func readTCPIoIntoStat(record *ringbuf.Record) (ebpf.Stat, error) {
	event, err := ebpfcommon.ReinterpretCast[ebpf.StatsTCPIo](record.RawSample)
	if err != nil {
		return ebpf.Stat{}, err
	}
	var total uint32
	for _, b := range event.Bytes[:min(int(event.Count), ebpf.TCPIoBatchSize)] {
		total += b
	}
	return ebpf.Stat{
		Type: ebpf.StatTypeTCPIo,
		TCPIo: &ebpf.TCPIo{
			Direction: event.Direction,
			Bytes:     total,
		},
		CommonAttrs: connToCommonAttrs(event.Conn),
	}, nil
}
