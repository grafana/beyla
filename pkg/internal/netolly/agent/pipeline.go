package agent

import (
	"context"

	"github.com/mariomac/pipes/pkg/graph"
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/export"
	"github.com/grafana/beyla/pkg/internal/netolly/export/otel"
	"github.com/grafana/beyla/pkg/internal/netolly/export/prom"
	"github.com/grafana/beyla/pkg/internal/netolly/flow"
	"github.com/grafana/beyla/pkg/internal/netolly/transform/cidr"
	"github.com/grafana/beyla/pkg/internal/netolly/transform/k8s"
)

// FlowsPipeline defines the different nodes in the Beyla's NetO11y module,
// as well as how they are interconnected
type FlowsPipeline struct {
	MapTracer     `sendTo:"Deduper"`
	RingBufTracer `sendTo:"Deduper"`

	Deduper    flow.Deduper          `forwardTo:"Kubernetes"`
	Kubernetes k8s.MetadataDecorator `forwardTo:"ReverseDNS"`
	ReverseDNS flow.ReverseDNS       `forwardTo:"CIDRs"`
	CIDRs      cidr.Definitions      `forwardTo:"Decorator"`
	Decorator  `sendTo:"OTEL,Prom,Printer"`

	OTEL    otel.MetricsConfig
	Prom    prom.PrometheusConfig
	Printer export.FlowPrinterEnabled
}

type MapTracer struct{}
type RingBufTracer struct{}
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

	alog.Debug("creating flows' processing graph")
	gb := graph.NewBuilder(node.ChannelBufferLen(f.cfg.ChannelBufferLen))

	// Start nodes: those generating flow records (reading them from eBPF)
	graph.RegisterStart(gb, func(_ MapTracer) (node.StartFunc[[]*ebpf.Record], error) {
		return f.mapTracer.TraceLoop(ctx), nil
	})
	graph.RegisterStart(gb, func(_ RingBufTracer) (node.StartFunc[[]*ebpf.Record], error) {
		return f.rbTracer.TraceLoop(ctx), nil
	})

	graph.RegisterMiddle(gb, flow.DeduperProvider)
	graph.RegisterMiddle(gb, func(_ Decorator) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		// If deduper is enabled, we know that interfaces are unset.
		// As an optimization, we just pass here an empty-string interface namer
		ifaceNamer := f.interfaceNamer
		if f.cfg.NetworkFlows.Deduper == flow.DeduperFirstCome {
			ifaceNamer = func(_ int) string {
				return ""
			}
		}
		return flow.Decorate(f.agentIP, ifaceNamer), nil
	})
	graph.RegisterMiddle(gb, cidr.DecoratorProvider)
	graph.RegisterMiddle(gb, func(cfg k8s.MetadataDecorator) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		return k8s.MetadataDecoratorProvider(ctx, cfg)
	})
	graph.RegisterMiddle(gb, flow.ReverseDNSProvider)

	// Terminal nodes export the flow record information out of the pipeline: OTEL and printer
	graph.RegisterTerminal(gb, otel.MetricsExporterProvider)
	graph.RegisterTerminal(gb, func(cfg prom.PrometheusConfig) (node.TerminalFunc[[]*ebpf.Record], error) {
		return prom.PrometheusEndpoint(ctx, &cfg, f.ctxInfo.Prometheus)
	})
	graph.RegisterTerminal(gb, export.FlowPrinterProvider)

	var deduperExpireTime = f.cfg.NetworkFlows.DeduperFCExpiry
	if deduperExpireTime <= 0 {
		deduperExpireTime = 2 * f.cfg.NetworkFlows.CacheActiveTimeout
	}
	return gb.Build(&FlowsPipeline{
		Deduper: flow.Deduper{
			Type:       f.cfg.NetworkFlows.Deduper,
			ExpireTime: deduperExpireTime,
		},
		Kubernetes: k8s.MetadataDecorator{Kubernetes: &f.cfg.Attributes.Kubernetes},
		// TODO: allow prometheus exporting
		ReverseDNS: f.cfg.NetworkFlows.ReverseDNS,
		CIDRs:      f.cfg.NetworkFlows.CIDRs,
		OTEL: otel.MetricsConfig{
			Metrics:           &f.cfg.Metrics,
			AllowedAttributes: f.cfg.NetworkFlows.AllowedAttributes,
		},
		Prom: prom.PrometheusConfig{
			Config:            &f.cfg.Prometheus,
			AllowedAttributes: f.cfg.NetworkFlows.AllowedAttributes,
		},
		Printer: export.FlowPrinterEnabled(f.cfg.NetworkFlows.Print),
	})
}
