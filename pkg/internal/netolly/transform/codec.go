package transform

import (
	"time"

	"github.com/grafana/beyla/pkg/internal/netolly/flow"
)

func RecordToMapCodec(in <-chan []*flow.Record, out chan<- []map[string]interface{}) {
	for flows := range in {
		maps := make([]map[string]interface{}, 0, cap(flows))
		for _, flow := range flows {
			maps = append(maps, flowToMap(flow))
		}
		out <- maps
	}
}

func flowToMap(flow *flow.Record) map[string]interface{} {
	return map[string]interface{}{
		"Etype":         int(flow.EthProtocol),
		"FlowDirection": int(flow.Direction),
		"SrcMac":        flow.DataLink.SrcMac.String(),
		"DstMac":        flow.DataLink.DstMac.String(),
		"SrcAddr":       flow.Network.SrcAddr.IP().String(),
		"DstAddr":       flow.Network.DstAddr.IP().String(),
		"SrcPort":       int(flow.Transport.SrcPort),
		"DstPort":       int(flow.Transport.DstPort),
		"Proto":         int(flow.Transport.Protocol),

		"Bytes":   int(flow.Bytes),
		"Packets": int(flow.Packets),

		"TimeFlowStartMs": flow.TimeFlowStart.UnixMilli(),
		"TimeFlowEndMs":   flow.TimeFlowEnd.UnixMilli(),
		"TimeReceived":    time.Now().Unix(), // TODO: probably unneeded
		"Interface":       flow.Interface,
		"Duplicate":       flow.Duplicate,

		"AgentIP": flow.AgentIP,
	}
}
