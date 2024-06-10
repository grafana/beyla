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
	attr2 "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
)

var (
	stateWaitAttr   = attr2.ProcCPUState.OTEL().String("wait")
	stateUserAttr   = attr2.ProcCPUState.OTEL().String("user")
	stateSystemAttr = attr2.ProcCPUState.OTEL().String("system")
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

	log *slog.Logger

	attrCPUTime []attributes.Field[*process.Status, attribute.KeyValue]
	attrCPUUtil []attributes.Field[*process.Status, attribute.KeyValue]

	// the observation code for CPU metrics will be different depending on
	// the "process.cpu.state" attribute being selected or not
	cpuTimeObserver        func(*procMetrics, *process.Status)
	cpuUtilisationObserver func(*procMetrics, *process.Status)
}

type procMetrics struct {
	ctx      context.Context
	service  *svc.ID
	provider *metric.MeterProvider

	cpuTime        *Expirer[*process.Status, metric2.Float64Observer, *FloatCounter, float64]
	cpuUtilisation *Expirer[*process.Status, metric2.Float64Observer, *Gauge, float64]
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

	attrCPUTime, cpuTimeHasState := cpuAttributes(attrProv, attributes.ProcessCPUTime)
	attrCPUUtil, cpuUtilHasState := cpuAttributes(attrProv, attributes.ProcessCPUUtilization)

	mr := &procMetricsExporter{
		ctx:         ctx,
		cfg:         cfg,
		clock:       expire.NewCachedClock(timeNow),
		attrCPUTime: attrCPUTime,
		attrCPUUtil: attrCPUUtil,
		log:         log,
	}
	if cpuTimeHasState {
		mr.cpuTimeObserver = cpuTimeDisaggregatedObserver
	} else {
		mr.cpuTimeObserver = cpuTimeAggregatedObserver
	}
	if cpuUtilHasState {
		mr.cpuUtilisationObserver = cpuUtilisationDisaggregatedObserver
	} else {
		mr.cpuUtilisationObserver = cpuUtilisationAggregatedObserver
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
	log := me.log.With("service", service)
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
		NewFloatCounter, me.attrCPUTime, timeNow, me.cfg.Metrics.TTL)
	if _, err := meter.Float64ObservableCounter(
		attributes.ProcessCPUTime.OTEL, metric2.WithUnit("s"),
		metric2.WithDescription("Total CPU seconds broken down by different states"),
		metric2.WithFloat64Callback(m.cpuTime.Collect),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	}

	m.cpuUtilisation = NewExpirer[*process.Status, metric2.Float64Observer](
		NewGauge, me.attrCPUUtil, timeNow, me.cfg.Metrics.TTL)
	if _, err := meter.Float64ObservableGauge(
		attributes.ProcessCPUUtilization.OTEL,
		metric2.WithDescription("Difference in process.cpu.time since the last measurement, divided by the elapsed time and number of CPUs available to the process"),
		metric2.WithUnit("1"),
		metric2.WithFloat64Callback(m.cpuUtilisation.Collect),
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
				me.log.Error("unexpected error creating OTEL resource. Ignoring metric",
					err, "service", s.Service)
				continue
			}
			me.log.Debug("reporting data for record", "record", s)

			// TODO: add more process metrics https://opentelemetry.io/docs/specs/semconv/system/process-metrics/
			me.cpuTimeObserver(reporter, s)
			me.cpuUtilisationObserver(reporter, s)
		}
	}
}

// aggregated observers report all the CPU metrics in a single data point
// to be triggered when the user disables the "process_cpu_state" metric
func cpuTimeAggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.cpuTime.ForRecord(record).
		Add(record.CPUTimeUserDelta + record.CPUTimeSystemDelta + record.CPUTimeWaitDelta)
}

func cpuUtilisationAggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.cpuUtilisation.ForRecord(record).
		Set(record.CPUUtilisationUser + record.CPUUtilisationSystem + record.CPUUtilisationWait)
}

// disaggregated observers report three CPU metrics: system, user and wait time
// to be triggered when the user enables the "process_cpu_state" metric
func cpuTimeDisaggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.cpuTime.ForRecord(record, stateWaitAttr).Add(record.CPUTimeWaitDelta)
	reporter.cpuTime.ForRecord(record, stateUserAttr).Add(record.CPUTimeUserDelta)
	reporter.cpuTime.ForRecord(record, stateSystemAttr).Add(record.CPUTimeSystemDelta)
}

func cpuUtilisationDisaggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.cpuUtilisation.ForRecord(record, stateWaitAttr).Set(record.CPUUtilisationWait)
	reporter.cpuUtilisation.ForRecord(record, stateUserAttr).Set(record.CPUUtilisationUser)
	reporter.cpuUtilisation.ForRecord(record, stateSystemAttr).Set(record.CPUUtilisationSystem)
}

// cpuAttributes returns, for a metric name definition, the getters for
// them. It also returns if the invoker must explicitly add the "process.cpu.state" name and value
func cpuAttributes(
	provider *attributes.AttrSelector, metricName attributes.Name,
) (
	getters []attributes.Field[*process.Status, attribute.KeyValue], containsState bool,
) {
	attrNames := provider.For(metricName)
	// "process_cpu_state" won't be added by OpenTelemetryGetters, as it's not defined in the *process.Status
	// we need to be aware of the user willing to add it to explicitly choose between
	// cpuTimeAggregatedObserver and cpuTimeDisggregatedObserver
	for _, attr := range attrNames {
		containsState = containsState || attr.OTEL() == attr2.ProcCPUState.OTEL()
	}
	getters = attributes.OpenTelemetryGetters(process.OTELGetters, attrNames)

	return
}
