package agent

import (
	"context"

	"github.com/mariomac/pipes/pipe"

	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/export/prom"
	"github.com/grafana/beyla/pkg/internal/filter"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/export"
	"github.com/grafana/beyla/pkg/internal/netolly/flow"
	"github.com/grafana/beyla/pkg/internal/netolly/transform/cidr"
	"github.com/grafana/beyla/pkg/internal/netolly/transform/k8s"
)

// FlowsPipeline defines the different nodes in the Beyla's NetO11y module,
// as well as how they are interconnected (in its Connect() method)
type FlowsPipeline struct {
	MapTracer     pipe.Start[[]*ebpf.Record]
	RingBufTracer pipe.Start[[]*ebpf.Record]

	ProtoFilter     pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	Deduper         pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	Kubernetes      pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	ReverseDNS      pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	CIDRs           pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	Decorator       pipe.Middle[[]*ebpf.Record, []*ebpf.Record]
	AttributeFilter pipe.Middle[[]*ebpf.Record, []*ebpf.Record]

	OTEL    pipe.Final[[]*ebpf.Record]
	Prom    pipe.Final[[]*ebpf.Record]
	Printer pipe.Final[[]*ebpf.Record]
}

// Connect specifies how the pipeline nodes are connected
func (fp *FlowsPipeline) Connect() {
	fp.MapTracer.SendTo(fp.ProtoFilter)
	fp.RingBufTracer.SendTo(fp.ProtoFilter)

	fp.ProtoFilter.SendTo(fp.Deduper)
	fp.Deduper.SendTo(fp.Kubernetes)
	fp.Kubernetes.SendTo(fp.ReverseDNS)
	fp.ReverseDNS.SendTo(fp.CIDRs)
	fp.CIDRs.SendTo(fp.Decorator)
	fp.Decorator.SendTo(fp.AttributeFilter)

	fp.AttributeFilter.SendTo(fp.OTEL, fp.Prom, fp.Printer)
}

// Accessory field pointer getters to later tell to the node providers where to store each pipeline Node
func mapTracer(fp *FlowsPipeline) *pipe.Start[[]*ebpf.Record]     { return &fp.MapTracer }
func ringBufTracer(fp *FlowsPipeline) *pipe.Start[[]*ebpf.Record] { return &fp.RingBufTracer }

func prtFltr(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]   { return &fp.ProtoFilter }
func deduper(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]   { return &fp.Deduper }
func kube(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]      { return &fp.Kubernetes }
func rdns(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]      { return &fp.ReverseDNS }
func cidrs(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]     { return &fp.CIDRs }
func decorator(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record] { return &fp.Decorator }
func fltr(fp *FlowsPipeline) *pipe.Middle[[]*ebpf.Record, []*ebpf.Record]      { return &fp.AttributeFilter }

func otelExport(fp *FlowsPipeline) *pipe.Final[[]*ebpf.Record] { return &fp.OTEL }
func promExport(fp *FlowsPipeline) *pipe.Final[[]*ebpf.Record] { return &fp.Prom }
func printer(fp *FlowsPipeline) *pipe.Final[[]*ebpf.Record]    { return &fp.Printer }

// buildPipeline creates the ETL flow processing graph.
// For a more visual view, check the docs/architecture.md document.
func (f *Flows) buildPipeline(ctx context.Context) (*pipe.Runner, error) {
	builder, err := f.pipelineBuilder(ctx)
	if err != nil {
		return nil, err
	}
	return builder.Build()
}

func (f *Flows) pipelineBuilder(ctx context.Context) (*pipe.Builder[*FlowsPipeline], error) {
	alog := alog()

	alog.Debug("creating flows' processing graph")
	pb := pipe.NewBuilder(&FlowsPipeline{}, pipe.ChannelBufferLen(f.cfg.ChannelBufferLen))

	// Start nodes: those generating flow records (reading them from eBPF)
	pipe.AddStart(pb, mapTracer, f.mapTracer.TraceLoop(ctx))
	pipe.AddStart(pb, ringBufTracer, f.rbTracer.TraceLoop(ctx))

	// Middle nodes: transforming flow records and passing them to the next stage in the pipeline.
	// Many of the nodes here are not mandatory. It's decision of each Provider function to decide
	// whether the node needs to be instantiated or just bypassed.
	pipe.AddMiddleProvider(pb, prtFltr,
		flow.ProtocolFilterProvider(f.cfg.NetworkFlows.Protocols, f.cfg.NetworkFlows.ExcludeProtocols))

	pipe.AddMiddleProvider(pb, deduper, func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		var deduperExpireTime = f.cfg.NetworkFlows.DeduperFCTTL
		if deduperExpireTime <= 0 {
			deduperExpireTime = 2 * f.cfg.NetworkFlows.CacheActiveTimeout
		}
		return flow.DeduperProvider(&flow.Deduper{
			Type:       f.cfg.NetworkFlows.Deduper,
			ExpireTime: deduperExpireTime,
		})
	})
	pipe.AddMiddleProvider(pb, decorator, func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
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
	pipe.AddMiddleProvider(pb, cidrs, func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		return cidr.DecoratorProvider(f.cfg.NetworkFlows.CIDRs)
	})
	pipe.AddMiddleProvider(pb, kube, func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		return k8s.MetadataDecoratorProvider(ctx, &f.cfg.Attributes.Kubernetes, f.ctxInfo.K8sInformer)
	})
	pipe.AddMiddleProvider(pb, rdns, func() (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
		return flow.ReverseDNSProvider(&f.cfg.NetworkFlows.ReverseDNS)
	})
	pipe.AddMiddleProvider(pb, fltr, filter.ByAttribute(f.cfg.Filters.Network, ebpf.RecordStringGetters))

	// Terminal nodes export the flow record information out of the pipeline: OTEL, Prom and printer.
	// Not all the nodes are mandatory here. Is the responsibility of each Provider function to decide
	// whether each node is going to be instantiated or just ignored.
	f.cfg.Attributes.Select.Normalize()
	pipe.AddFinalProvider(pb, otelExport, func() (pipe.FinalFunc[[]*ebpf.Record], error) {
		return otel.NetMetricsExporterProvider(ctx, f.ctxInfo, &otel.NetMetricsConfig{
			Metrics:            &f.cfg.Metrics,
			AttributeSelectors: f.cfg.Attributes.Select,
			GloballyEnabled:    f.cfg.NetworkFlows.Enable,
		})
	})
	pipe.AddFinalProvider(pb, promExport, func() (pipe.FinalFunc[[]*ebpf.Record], error) {
		return prom.NetPrometheusEndpoint(ctx, f.ctxInfo, &prom.NetPrometheusConfig{
			Config:             &f.cfg.Prometheus,
			AttributeSelectors: f.cfg.Attributes.Select,
			GloballyEnabled:    f.cfg.NetworkFlows.Enable,
		})
	})
	pipe.AddFinalProvider(pb, printer, func() (pipe.FinalFunc[[]*ebpf.Record], error) {
		return export.FlowPrinterProvider(f.cfg.NetworkFlows.Print)
	})

	return pb, nil
}
