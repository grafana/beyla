// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.38.0"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// NetMetricsConfig extends MetricsConfig for Network Metrics
type NetMetricsConfig struct {
	Metrics     *otelcfg.MetricsConfig
	CommonCfg   *perapp.MetricsConfig
	SelectorCfg *attributes.SelectorConfig
}

func (mc *NetMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() &&
		mc.CommonCfg.Features.AnyNetwork()
}

func nmlog() *slog.Logger {
	return slog.With("component", "otel.NetworkMetricsExporter")
}

// getFilteredNetworkResourceAttrs returns resource attributes that can be filtered based on the attribute selector
// for network metrics.
func getFilteredNetworkResourceAttrs(hostID string, attrSelector attributes.Selection) []attribute.KeyValue {
	baseAttrs := []attribute.KeyValue{
		attribute.String(attr.VendorPrefix+string(attr.VendorVersionSuffix), buildinfo.Version),
		attribute.String(attr.VendorPrefix+string(attr.VendorRevisionSuffix), buildinfo.Revision),
	}

	extraAttrs := []attribute.KeyValue{
		semconv.HostID(hostID),
	}

	return otelcfg.GetFilteredAttributesByPrefix(baseAttrs, attrSelector, extraAttrs, []string{"network.", attr.VendorPrefix + ".network"})
}

func createFilteredNetworkResource(hostID string, attrSelector attributes.Selection) *resource.Resource {
	attrs := getFilteredNetworkResourceAttrs(hostID, attrSelector)
	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

func newMeterProvider(res *resource.Resource, exporter *sdkmetric.Exporter, interval time.Duration) *metric.MeterProvider {
	return metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
}

type netMetricsExporter struct {
	flowBytes      *Expirer[*ebpf.Record, metric2.Int64Counter, float64]
	interZoneBytes *Expirer[*ebpf.Record, metric2.Int64Counter, float64]
	clock          *expire.CachedClock
	expireTTL      time.Duration
	in             <-chan []*ebpf.Record
}

func NetMetricsExporterProvider(
	ctxInfo *global.ContextInfo,
	cfg *NetMetricsConfig,
	input *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the swarm library just ignore it.
			return swarm.EmptyRunFunc()
		}
		if cfg.SelectorCfg.SelectionCfg == nil {
			cfg.SelectorCfg.SelectionCfg = make(attributes.Selection)
		}
		exporter, err := newMetricsExporter(ctx, ctxInfo, cfg, input)
		if err != nil {
			return nil, err
		}
		return exporter.Do, nil
	}
}

func newMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *NetMetricsConfig,
	input *msg.Queue[[]*ebpf.Record],
) (*netMetricsExporter, error) {
	log := nmlog()
	log.Debug("instantiating network metrics exporter provider")
	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}
	exporter = instrumentMetricsExporter(ctxInfo.Metrics, exporter)

	resource := createFilteredNetworkResource(ctxInfo.HostID, cfg.SelectorCfg.SelectionCfg)
	provider := newMeterProvider(resource, &exporter, cfg.Metrics.Interval)

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("network OTEL exporter attributes enable: %w", err)
	}

	clock := expire.NewCachedClock(timeNow)

	ebpfEvents := provider.Meter("network_ebpf_events")

	nme := &netMetricsExporter{
		clock:     clock,
		expireTTL: cfg.Metrics.TTL,
	}
	if cfg.CommonCfg.Features.NetworkBytes() {
		log := log.With("metricFamily", "FlowBytes")
		bytesMetric, err := ebpfEvents.Int64Counter(attributes.NetworkFlow.OTEL,
			metric2.WithDescription("total bytes_sent value of network flows observed by probe since its launch"),
			metric2.WithUnit("{bytes}"), // TODO: By?
		)
		if err != nil {
			log.Error("creating observable counter", "error", err)
			return nil, err
		}

		log.Debug("restricting attributes not in this list", "attributes", cfg.SelectorCfg.SelectionCfg)
		attrs := attributes.OpenTelemetryGetters(
			ebpf.RecordGetters,
			attrProv.For(attributes.NetworkFlow))

		nme.flowBytes = NewExpirer[*ebpf.Record, metric2.Int64Counter, float64](ctx, bytesMetric, attrs, clock.Time, cfg.Metrics.TTL)
	}

	if cfg.CommonCfg.Features.NetworkInterZone() {
		log := log.With("metricFamily", "InterZoneBytes")
		bytesMetric, err := ebpfEvents.Int64Counter(attributes.NetworkInterZone.OTEL,
			metric2.WithDescription("total bytes_sent value between Cloud availability zones"),
			metric2.WithUnit("{bytes}"), // TODO: By?
		)
		if err != nil {
			log.Error("creating observable counter", "error", err)
			return nil, err
		}
		log.Debug("restricting attributes not in this list", "attributes", cfg.SelectorCfg.SelectionCfg)
		attrs := attributes.OpenTelemetryGetters(
			ebpf.RecordGetters,
			attrProv.For(attributes.NetworkInterZone))

		nme.interZoneBytes = NewExpirer[*ebpf.Record, metric2.Int64Counter, float64](ctx, bytesMetric, attrs, clock.Time, cfg.Metrics.TTL)
	}

	nme.in = input.Subscribe(msg.SubscriberName("otel.NetMetricsExporter"))
	return nme, nil
}

func (me *netMetricsExporter) Do(ctx context.Context) {
	for i := range me.in {
		me.clock.Update()
		for _, v := range i {
			if me.flowBytes != nil {
				flowBytes, attrs := me.flowBytes.ForRecord(v)
				flowBytes.Add(ctx, int64(v.Metrics.Bytes), metric2.WithAttributeSet(attrs))
			}
			if me.interZoneBytes != nil && v.Attrs.SrcZone != v.Attrs.DstZone {
				izBytes, attrs := me.interZoneBytes.ForRecord(v)
				izBytes.Add(ctx, int64(v.Metrics.Bytes), metric2.WithAttributeSet(attrs))
			}
		}
	}
}
