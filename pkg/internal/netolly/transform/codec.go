package transform

import (
	"time"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
)

func RecordToMapCodec(in <-chan []*ebpf.Record, out chan<- []map[string]interface{}) {
	for flows := range in {
		maps := make([]map[string]interface{}, 0, cap(flows))
		for _, flow := range flows {
			maps = append(maps, flowToMap(flow))
		}
		out <- maps
	}
}

func flowToMap(flow *ebpf.Record) map[string]interface{} {
	return map[string]interface{}{
		"Etype":         int(flow.Id.EthProtocol),
		"FlowDirection": int(flow.Id.Direction),
		"SrcMac":        flow.Id.SrcMAC().String(),
		"DstMac":        flow.Id.DstMAC().String(),
		"SrcAddr":       flow.Id.SrcIP().IP().String(),
		"DstAddr":       flow.Id.DstIP().IP().String(),
		"SrcPort":       int(flow.Id.SrcPort),
		"DstPort":       int(flow.Id.DstPort),
		"Proto":         int(flow.Id.TransportProtocol),

		"Bytes":   int(flow.Metrics.Bytes),
		"Packets": int(flow.Metrics.Packets),

		"TimeFlowStartMs": flow.TimeFlowStart.UnixMilli(),
		"TimeFlowEndMs":   flow.TimeFlowEnd.UnixMilli(),
		"TimeReceived":    time.Now().Unix(), // TODO: probably unneeded
		"Interface":       flow.Interface,
		"Duplicate":       flow.Duplicate,

		"AgentIP": flow.AgentIP,
	}
}
