package agent

import (
	"context"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/beyla/flows/export"
	flow2 "github.com/grafana/beyla/pkg/beyla/flows/flow"
	"github.com/grafana/beyla/pkg/beyla/flows/transform"
)

type FlowsPipeline struct {
	MapTracer       `sendTo:"Deduper"`
	RingBufTracer   `sendTo:"Accounter"`
	Accounter       `sendTo:"Deduper"`
	Deduper         flow2.Deduper `forwardTo:"CapacityLimiter"`
	CapacityLimiter `sendTo:"Decorator"`
	//Decorator       `sendTo:"Kubernetes"`
	Decorator `sendTo:"Exporter"`

	Kubernetes *transform.NetworkTransformConfig `sendTo:"Exporter"`

	Exporter export.ExportConfig
}

type Codec struct{}
type MapTracer struct{}
type RingBufTracer struct{}
type Accounter struct{}
type CapacityLimiter struct{}
type Decorator struct{}

// buildAndStartPipeline creates the ETL flow processing graph.
// For a more visual view, check the docs/architecture.md document.
func (f *Flows) buildAndStartPipeline(ctx context.Context) (graph.Graph, error) {
	alog := alog()
	alog.Debug("registering interfaces' listener in background")
	err := f.interfacesManager(ctx)
	if err != nil {
		return graph.Graph{}, err
	}
	ebl := f.cfg.ExporterBufferLength
	if ebl == 0 {
		ebl = f.cfg.BuffersLength
	}

	alog.Debug("creating flows' processing graph")
	gb := graph.NewBuilder(node.ChannelBufferLen(f.cfg.BuffersLength))
	// A codec allows automatically connecting a node whose output is []*flow2.Record with a node
	// whose input is []map[string]interface{}]
	graph.RegisterCodec(gb, transform.RecordToMapCodec)

	graph.RegisterStart(gb, func(_ MapTracer) (node.StartFunc[[]*flow2.Record], error) {
		return f.mapTracer.TraceLoop(ctx), nil
	})
	graph.RegisterStart(gb, func(_ RingBufTracer) (node.StartFunc[*flow2.RawRecord], error) {
		return f.rbTracer.TraceLoop(ctx), nil
	})
	graph.RegisterMiddle(gb, func(_ Accounter) (node.MiddleFunc[*flow2.RawRecord, []*flow2.Record], error) {
		return f.accounter.Account, nil
	})
	graph.RegisterMiddle(gb, flow2.DeduperProvider)
	graph.RegisterMiddle(gb, func(_ CapacityLimiter) (node.MiddleFunc[[]*flow2.Record, []*flow2.Record], error) {
		return (&flow2.CapacityLimiter{}).Limit, nil
	})
	graph.RegisterMiddle(gb, func(_ Decorator) (node.MiddleFunc[[]*flow2.Record, []*flow2.Record], error) {
		return flow2.Decorate(f.agentIP, f.interfaceNamer), nil
	})
	graph.RegisterMiddle(gb, transform.Network)

	graph.RegisterTerminal(gb, export.ExporterProvider)

	return gb.Build(&FlowsPipeline{
		Deduper: flow2.Deduper{
			Type:       f.cfg.Deduper,
			ExpireTime: f.cfg.DeduperFCExpiry,
			JustMark:   f.cfg.DeduperJustMark,
		},
		Kubernetes: &f.cfg.Transform,
		// TODO: put here any extra configuration for the exporter
		Exporter: export.ExportConfig{},
	})
}
