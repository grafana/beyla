package otel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/buildinfo"
	"github.com/grafana/beyla/pkg/export/attributes"
	"github.com/grafana/beyla/pkg/export/expire"
	"github.com/grafana/beyla/pkg/export/otel/metric"
	metric2 "github.com/grafana/beyla/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// NetMetricsConfig extends MetricsConfig for Network Metrics
type NetMetricsConfig struct {
	Metrics            *MetricsConfig
	AttributeSelectors attributes.Selection
	GloballyEnabled    bool
}

func (mc NetMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() && (mc.Metrics.NetworkMetricsEnabled() || mc.GloballyEnabled)
}

func nmlog() *slog.Logger {
	return slog.With("component", "otel.NetworkMetricsExporter")
}

func newResource(hostID string) *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.ServiceName("beyla-network-flows"),
		semconv.ServiceInstanceID(uuid.New().String()),
		// SpanMetrics requires an extra attribute besides service name
		// to generate the traces_target_info metric,
		// so the service is visible in the ServicesList
		// This attribute also allows that App O11y plugin shows this app as a Go application.
		semconv.TelemetrySDKLanguageKey.String(semconv.TelemetrySDKLanguageGo.Value.AsString()),
		// We set the SDK name as Beyla, so we can distinguish beyla generated metrics from other SDKs
		semconv.TelemetrySDKNameKey.String("beyla"),
		semconv.TelemetrySDKVersion(buildinfo.Version),
		semconv.HostID(hostID),
	}

	return resource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

func newMeterProvider(res *resource.Resource, exporter *sdkmetric.Exporter, interval time.Duration) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
	return meterProvider, nil
}

type netMetricsExporter struct {
	ctx            context.Context
	flowBytes      *Expirer[*ebpf.Record, metric2.Int64Counter, float64]
	interZoneBytes *Expirer[*ebpf.Record, metric2.Int64Counter, float64]
	clock          *expire.CachedClock
	expireTTL      time.Duration
}

func NetMetricsExporterProvider(ctx context.Context, ctxInfo *global.ContextInfo, cfg *NetMetricsConfig) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
	exporter, err := newMetricsExporter(ctx, ctxInfo, cfg)
	if err != nil {
		return nil, err
	}
	return exporter.Do, nil
}

func newMetricsExporter(ctx context.Context, ctxInfo *global.ContextInfo, cfg *NetMetricsConfig) (*netMetricsExporter, error) {
	log := nmlog()
	log.Debug("instantiating network metrics exporter provider")
	exporter, err := InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("can't instantiate metrics exporter", "error", err)
		return nil, err
	}

	provider, err := newMeterProvider(newResource(ctxInfo.HostID), &exporter, cfg.Metrics.Interval)

	if err != nil {
		log.Error("can't instantiate meter provider", "error", err)
		return nil, err
	}

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network OTEL exporter attributes enable: %w", err)
	}
	attrs := attributes.OpenTelemetryGetters(
		ebpf.RecordGetters,
		attrProv.For(attributes.BeylaNetworkFlow))

	clock := expire.NewCachedClock(timeNow)

	ebpfEvents := provider.Meter("network_ebpf_events")

	nme := &netMetricsExporter{
		ctx:       ctx,
		clock:     clock,
		expireTTL: cfg.Metrics.TTL,
	}
	if cfg.Metrics.NetworkFlowBytesEnabled() {
		log := log.With("metricFamily", "FlowBytes")
		bytesMetric, err := ebpfEvents.Int64Counter(attributes.BeylaNetworkFlow.OTEL,
			metric2.WithDescription("total bytes_sent value of network flows observed by probe since its launch"),
			metric2.WithUnit("{bytes}"), // TODO: By?
		)
		if err != nil {
			log.Error("creating observable counter", "error", err)
			return nil, err
		}

		log.Debug("restricting attributes not in this list", "attributes", cfg.AttributeSelectors)
		nme.flowBytes = NewExpirer[*ebpf.Record, metric2.Int64Counter, float64](ctx, bytesMetric, attrs, clock.Time, cfg.Metrics.TTL)
	}

	if cfg.Metrics.NetworkInterzoneMetricsEnabled() {
		log := log.With("metricFamily", "InterZoneBytes")
		bytesMetric, err := ebpfEvents.Int64Counter(attributes.BeylaNetworkInterZone.OTEL,
			metric2.WithDescription("total bytes_sent value between Cloud availability zones"),
			metric2.WithUnit("{bytes}"), // TODO: By?
		)
		if err != nil {
			log.Error("creating observable counter", "error", err)
			return nil, err
		}
		nme.interZoneBytes = NewExpirer[*ebpf.Record, metric2.Int64Counter, float64](ctx, bytesMetric, attrs, clock.Time, cfg.Metrics.TTL)
		log.Debug("restricting attributes not in this list", "attributes", cfg.AttributeSelectors)
	}

	return nme, nil
}

func (me *netMetricsExporter) Do(in <-chan []*ebpf.Record) {
	for i := range in {
		me.clock.Update()
		for _, v := range i {
			if me.flowBytes != nil {
				flowBytes, attrs := me.flowBytes.ForRecord(v)
				flowBytes.Add(me.ctx, int64(v.Metrics.Bytes), metric2.WithAttributeSet(attrs))
			}
			if me.interZoneBytes != nil && v.Attrs.SrcZone != v.Attrs.DstZone {
				izBytes, attrs := me.flowBytes.ForRecord(v)
				izBytes.Add(me.ctx, int64(v.Metrics.Bytes), metric2.WithAttributeSet(attrs))
			}
		}
	}
}
