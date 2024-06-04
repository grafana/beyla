package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// ProcMetricsConfig extends MetricsConfig for process metrics
type ProcMetricsConfig struct {
	Metrics            *MetricsConfig
	AttributeSelectors attributes.Selection
}

func (mc *ProcMetricsConfig) Enabled() bool {
	return mc.Metrics != nil && mc.Metrics.EndpointEnabled() && mc.Metrics.OTelMetricsEnabled() &&
		slices.Contains(mc.Metrics.Features, FeatureProcess)
}

func pmlog() *slog.Logger {
	return slog.With("component", "otel.ProcMetricsExporter")
}

type procMetricsExporter struct {
	ctx   context.Context
	cfg   *ProcMetricsConfig
	clock *expire.CachedClock

	exporter  metric.Exporter
	reporters ReporterPool[*procMetrics]

	attrCPUTime []attributes.Field[*process.Status, attribute.KeyValue]
}

type procMetrics struct {
	ctx      context.Context
	service  *svc.ID
	provider *metric.MeterProvider

	cpuTime *Expirer[*process.Status, metric2.Float64Observer, *Gauge, float64]
}

func ProcMetricsExporterProvider(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *ProcMetricsConfig,
) pipe.FinalProvider[[]*process.Status] {
	return func() (pipe.FinalFunc[[]*process.Status], error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return pipe.IgnoreFinal[[]*process.Status](), nil
		}
		return newProcMetricsExporter(ctx, ctxInfo, cfg)
	}
}

func newProcMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *ProcMetricsConfig,
) (pipe.FinalFunc[[]*process.Status], error) {
	SetupInternalOTELSDKLogger(cfg.Metrics.SDKLogLevel)

	log := pmlog()
	log.Debug("instantiating process metrics exporter provider")

	// only user-provided attributes (or default set) will decorate the metrics
	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("process OTEL exporter attributes: %w", err)
	}

	mr := &procMetricsExporter{
		ctx:   ctx,
		cfg:   cfg,
		clock: expire.NewCachedClock(timeNow),
		attrCPUTime: attributes.OpenTelemetryGetters(
			process.OTELGetters, attrProv.For(attributes.ProcessCPUUtilization)),
	}

	mr.reporters = NewReporterPool[*procMetrics](cfg.Metrics.ReportersCacheLen,
		func(id svc.UID, v *procMetrics) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)

	mr.exporter, err = InstantiateMetricsExporter(ctx, cfg.Metrics, log)
	if err != nil {
		log.Error("instantiating metrics exporter", "error", err)
		return nil, err
	}

	return mr.Do, nil
}

func (me *procMetricsExporter) newMetricSet(service *svc.ID) (*procMetrics, error) {
	log := pmlog().With("service", service)
	log.Debug("creating new Metrics exporter")
	resources := getResourceAttrs(service)
	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(me.exporter,
			metric.WithInterval(me.cfg.Metrics.Interval))),
	}

	m := procMetrics{
		ctx:      me.ctx,
		service:  service,
		provider: metric.NewMeterProvider(opts...),
	}

	meter := m.provider.Meter(reporterName)
	m.cpuTime = NewExpirer[*process.Status, metric2.Float64Observer](
		NewGauge,
		me.attrCPUTime,
		timeNow,
		me.cfg.Metrics.TTL,
	)
	if _, err := meter.Float64ObservableGauge(
		attributes.ProcessCPUUtilization.OTEL,
		metric2.WithDescription("TODO"),
		metric2.WithUnit("1"),
		metric2.WithFloat64Callback(m.cpuTime.Collect),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	}

	return &m, nil
}

// Do reads all the process status data points and create the metrics accordingly
func (me *procMetricsExporter) Do(in <-chan []*process.Status) {
	for i := range in {
		me.clock.Update()
		for _, s := range i {
			reporter, err := me.reporters.For(s.Service)
			if err != nil {
				pmlog().Error("unexpected error creating OTEL resource. Ignoring metric",
					err, "service", s.Service)
				continue
			}
			pmlog().Debug("reporting data for record", "record", s)
			// TODO: support user/system/other
			reporter.cpuTime.ForRecord(s).Set(s.CPUPercent)
		}
	}
}
