package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	otel2 "github.com/grafana/beyla/pkg/internal/netolly/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
)

var timeNow = time.Now

type MetricsConfig struct {
	Metrics            *otel.MetricsConfig
	AttributeSelectors attributes.Selection
}

func (mc MetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() && slices.Contains(mc.Metrics.Features, otel.FeatureProcess)
}

func mlog() *slog.Logger {
	return slog.With("component", "otel.ProcessMetricsExporter")
}

func newMeterProvider(res *resource.Resource, exporter *metric.Exporter, interval time.Duration) (*metric.MeterProvider, error) {
	meterProvider := metric.NewMeterProvider(
		metric.WithResource(res),
		metric.WithReader(metric.NewPeriodicReader(*exporter, metric.WithInterval(interval))),
	)
	return meterProvider, nil
}

type metricsExporter struct {
	metrics *otel2.Expirer
	clock   *expire.CachedClock
}

func ProcessMetricsExporterProvider(ctxInfo *global.ContextInfo, cfg *MetricsConfig) (pipe.FinalFunc[[]*ebpf.Record], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*ebpf.Record](), nil
	}
	log := mlog()
	log.Debug("instantiating network metrics exporter provider")
	exporter, err := otel.InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("", "error", err)
		return nil, err
	}

	provider, err := newMeterProvider(otel.ResourceAttrs(), &exporter, cfg.Metrics.Interval)

	if err != nil {
		log.Error("", "error", err)
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
	expirer := otel2.NewExpirer(attrs, clock.Time, cfg.Metrics.TTL)
	ebpfEvents := provider.Meter("network_ebpf_events")

	_, err = ebpfEvents.Int64ObservableCounter(
		attributes.BeylaNetworkFlow.OTEL,
		metric2.WithDescription("total bytes_sent value of network flows observed by probe since its launch"),
		metric2.WithUnit("{bytes}"),
		metric2.WithInt64Callback(expirer.Collect),
	)
	if err != nil {
		log.Error("creating observable counter", "error", err)
		return nil, err
	}
	log.Debug("restricting attributes not in this list", "attributes", cfg.AttributeSelectors)
	return (&metricsExporter{
		metrics: expirer,
		clock:   clock,
	}).Do, nil
}

func (me *metricsExporter) Do(in <-chan []*ebpf.Record) {
	for i := range in {
		me.clock.Update()
		for _, v := range i {
			me.metrics.CounterForRecord(v).val.Add(int64(v.Metrics.Bytes))
		}
	}
}
