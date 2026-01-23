// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agent // import "go.opentelemetry.io/obi/pkg/netolly/agent"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/prom"
	"go.opentelemetry.io/obi/pkg/filter"
	msgh "go.opentelemetry.io/obi/pkg/internal/helpers/msg"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/internal/netolly/export"
	"go.opentelemetry.io/obi/pkg/internal/netolly/flow"
	"go.opentelemetry.io/obi/pkg/internal/netolly/transform/k8s"
	"go.opentelemetry.io/obi/pkg/netolly/cidr"
	"go.opentelemetry.io/obi/pkg/netolly/flowdef"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// mockable functions for testing
var newMapTracer = func(f *Flows, out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return f.mapTracer.TraceLoop(out)
}

var newRingBufTracer = func(f *Flows, out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return f.rbTracer.TraceLoop(out)
}

// buildPipeline defines the different nodes in the Beyla's NetO11y module,
// as well as how they are interconnected (in its Connect() method)
func (f *Flows) buildPipeline(ctx context.Context) (*swarm.Runner, error) {
	alog := alog()

	alog.Debug("creating flows' processing graph")

	selectorCfg := &attributes.SelectorConfig{
		SelectionCfg:            f.cfg.Attributes.Select,
		ExtraGroupAttributesCfg: f.cfg.Attributes.ExtraGroupAttributes,
	}

	swi := &swarm.Instancer{}
	// Start nodes: those generating flow records (reading them from eBPF)
	ebpfFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "ebpfFlows")
	swi.Add(swarm.DirectInstance(newMapTracer(f, ebpfFlows)), swarm.WithID("MapTracer"))
	swi.Add(swarm.DirectInstance(newRingBufTracer(f, ebpfFlows)), swarm.WithID("RingBufTracer"))

	// Middle nodes: transforming flow records and passing them to the next stage in the pipeline.
	// Many of the nodes here are not mandatory. It's decision of each InstanceFunc to decide
	// whether the node needs to be instantiated or just bypass their input/output channels.
	protocolFilteredEbpfFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "protocolFilteredEbpfFlows")
	swi.Add(flow.ProtocolFilterProvider(f.cfg.NetworkFlows.Protocols, f.cfg.NetworkFlows.ExcludeProtocols,
		ebpfFlows, protocolFilteredEbpfFlows), swarm.WithID("ProtocolFilter"))

	dedupedEBPFFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "dedupedEBPFFlows")
	swi.Add(flow.DeduperProvider(&flow.Deduper{
		Type:               f.cfg.NetworkFlows.Deduper,
		FCTTL:              f.cfg.NetworkFlows.DeduperFCTTL,
		CacheActiveTimeout: f.cfg.NetworkFlows.CacheActiveTimeout,
	}, protocolFilteredEbpfFlows, dedupedEBPFFlows), swarm.WithID("FlowDeduper"))

	kubeDecoratedFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "kubeDecoratedFlows")
	swi.Add(k8s.MetadataDecoratorProvider(ctx, &f.cfg.Attributes.Kubernetes, f.ctxInfo.K8sInformer,
		dedupedEBPFFlows, kubeDecoratedFlows), swarm.WithID("K8sMetadataDecorator"))

	dnsDecoratedFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "dnsDecoratedFlows")
	swi.Add(flow.ReverseDNSProvider(&f.cfg.NetworkFlows.ReverseDNS, kubeDecoratedFlows, dnsDecoratedFlows),
		swarm.WithID("ReverseDNS"))

	geoIPDecoratedFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "geoIPDecoratedFlows")
	swi.Add(flow.GeoIPProvider(&f.cfg.NetworkFlows.GeoIP,
		dnsDecoratedFlows, geoIPDecoratedFlows), swarm.WithID("GeoIPDecorator"))

	cidrDecoratedFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "cidrDecoratedFlows")
	swi.Add(cidr.DecoratorProvider(f.cfg.NetworkFlows.CIDRs, geoIPDecoratedFlows, cidrDecoratedFlows),
		swarm.WithID("CIDRDecorator"))

	decoratedFlows := msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "decoratedFlows")
	swi.Add(func(_ context.Context) (swarm.RunFunc, error) {
		// If deduper is enabled, we know that interfaces are unset.
		// As an optimization, we just pass here an empty-string interface namer
		ifaceNamer := f.interfaceNamer
		if f.cfg.NetworkFlows.Deduper == flowdef.DeduperFirstCome {
			ifaceNamer = func(_ int) string {
				return ""
			}
		}
		return flow.Decorate(f.agentIP, ifaceNamer, cidrDecoratedFlows, decoratedFlows), nil
	}, swarm.WithID("FlowDecorator"))

	filteredFlows := f.ctxInfo.OverrideNetExportQueue
	if filteredFlows == nil {
		filteredFlows = msgh.QueueFromConfig[[]*ebpf.Record](f.cfg, "filteredFlows")
	}
	swi.Add(filter.ByAttribute(f.cfg.Filters.Network, nil, selectorCfg.ExtraGroupAttributesCfg, ebpf.RecordStringGetters, decoratedFlows, filteredFlows),
		swarm.WithID("AttributeFilter"))

	// Terminal nodes export the flow record information out of the pipeline: OTEL, Prom and printer.
	// Not all the nodes are mandatory here. Is the responsibility of each Provider function to decide
	// whether each node is going to be instantiated or just ignored.
	swi.Add(otel.NetMetricsExporterProvider(f.ctxInfo, &otel.NetMetricsConfig{
		Metrics:     &f.cfg.OTELMetrics,
		SelectorCfg: selectorCfg,
		CommonCfg:   &f.cfg.Metrics,
	}, filteredFlows), swarm.WithID("OTelExporter"))

	swi.Add(prom.NetPrometheusEndpoint(f.ctxInfo, &prom.NetPrometheusConfig{
		Config:      &f.cfg.Prometheus,
		SelectorCfg: selectorCfg,
		CommonCfg:   &f.cfg.Metrics,
	}, filteredFlows), swarm.WithID("PrometheusExporter"))

	swi.Add(swarm.DirectInstance(export.FlowPrinterProvider(f.cfg.NetworkFlows.Print, filteredFlows)),
		swarm.WithID("FlowPrinter"))

	return swi.Instance(ctx)
}
