package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	metric2 "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	otel2 "github.com/grafana/beyla/pkg/internal/netolly/export/otel"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
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
	ctx   context.Context
	cfg   *MetricsConfig
	clock *expire.CachedClock

	attributes *attributes.AttrSelector
	exporter   metric.Exporter
	reporters  otel.ReporterPool[*Metrics]

	attrCPUTime []attributes.Field[*process.Status, attribute.KeyValue]
}

type Metrics struct {
	ctx      context.Context
	service  svc.ID
	provider *metric.MeterProvider

	cpuTime *otel2.Expirer[*process.Status, metric2.Float64Observer, *otel2.Gauge, float64]
}

func ProcessMetricsExporterProvider(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *MetricsConfig,
) (pipe.FinalFunc[[]*process.Status], error) {
	if !cfg.Enabled() {
		// This node is not going to be instantiated. Let the pipes library just ignore it.
		return pipe.IgnoreFinal[[]*process.Status](), nil
	}
	otel.SetupInternalOTELSDKLogger(cfg.Metrics.SDKLogLevel)

	log := mlog()
	log.Debug("instantiating process metrics exporter provider")

	attrProv, err := attributes.NewAttrSelector(ctxInfo.MetricAttributeGroups, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("process OTEL exporter attributes enable: %w", err)
	}

	mr := &metricsExporter{
		ctx:        ctx,
		cfg:        cfg,
		attributes: attrProv,
	}

	mr.attrCPUTime = attributes.OpenTelemetryGetters(
		process.OTELGetters, mr.attributes.For(attributes.ProcessCPUUtilization))

	mr.reporters = otel.NewReporterPool[*Metrics](cfg.Metrics.ReportersCacheLen,
		func(id svc.UID, v *Metrics) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)

	mr.exporter, err = otel.InstantiateMetricsExporter(context.Background(), cfg.Metrics, log)
	if err != nil {
		log.Error("instantiating metrics exporter", "error", err)
		return nil, err
	}

	return mr.Do, nil
}

func (mr *metricsExporter) newMetricSet(service svc.ID) (*Metrics, error) {
	log := mlog().With("service", service)
	log.Debug("creating new Metrics exporter")
	resources := otel.ResourceAttrs(service)
	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(mr.exporter,
			metric.WithInterval(mr.cfg.Metrics.Interval))),
	}

	m := Metrics{
		ctx:      mr.ctx,
		service:  service,
		provider: metric.NewMeterProvider(opts...),
	}

	// TODO: reporterName must go somewhere
	//meter := m.provider.Meter(otel.ReporterName)
	m.cpuTime = otel2.NewExpirer[*process.Status, metric2.Float64Observer](
		otel2.NewGauge,
		mr.attrCPUTime,
		timeNow,
		mr.cfg.Metrics.TTL,
	)
	return &m, nil
}

func (me *metricsExporter) Do(in <-chan []*process.Status) {
	var lastSvcUID svc.UID
	var reporter *Metrics
	for i := range in {
		me.clock.Update()
		for _, s := range i {
			// optimization: do not query the resources' cache if the
			// previously processed span belongs to the same service name
			// as the current.
			// This will save querying OTEL resource reporters when there is
			// only a single instrumented process.
			// In multi-process tracing, this is likely to happen as most
			// tracers group traces belonging to the same service in the same slice.
			if s.ServiceID.UID != lastSvcUID || reporter == nil {
				lm, err := me.reporters.For(s.ServiceID)
				if err != nil {
					mlog().Error("unexpected error creating OTEL resource. Ignoring metric",
						err, "service", s.ServiceID)
					continue
				}
				lastSvcUID = s.ServiceID.UID
				reporter = lm
			}
			// TODO: support user/system/other
			// TODO: precalculate For UUID
			lm.cpuTime.ForRecord(s).Set(s.CPUSystemPercent)
			lm.cpuTime.ForRecord(s).Set(s.CPUUserPercent)
			lm.cpuTime.ForRecord(s).Set(s.CPUPercent)
		}
	}
}
