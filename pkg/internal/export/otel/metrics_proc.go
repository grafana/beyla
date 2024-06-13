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

	diskIODirRead  = attr2.ProcDiskIODir.OTEL().String("read")
	diskIODirWrite = attr2.ProcDiskIODir.OTEL().String("write")
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

	attrCPUTime       []attributes.Field[*process.Status, attribute.KeyValue]
	attrCPUUtil       []attributes.Field[*process.Status, attribute.KeyValue]
	attrMemory        []attributes.Field[*process.Status, attribute.KeyValue]
	attrMemoryVirtual []attributes.Field[*process.Status, attribute.KeyValue]
	attrDisk          []attributes.Field[*process.Status, attribute.KeyValue]

	// the observation code for CPU metrics will be different depending on
	// the "process.cpu.state" attribute being selected or not
	cpuTimeObserver        func(*procMetrics, *process.Status)
	cpuUtilisationObserver func(*procMetrics, *process.Status)

	// the observation code for disk metrics will be different depending on
	// the disk.io.direction attribute being selected or not
	diskObserver func(*procMetrics, *process.Status)
}

type procMetrics struct {
	ctx      context.Context
	service  *svc.ID
	provider *metric.MeterProvider

	cpuTime        *Expirer[*process.Status, metric2.Float64Observer, *FloatCounter, float64]
	cpuUtilisation *Expirer[*process.Status, metric2.Float64Observer, *Gauge, float64]
	memory         *Expirer[*process.Status, metric2.Int64Observer, *IntGauge, int64]
	memoryVirtual  *Expirer[*process.Status, metric2.Int64Observer, *IntGauge, int64]
	disk           *Expirer[*process.Status, metric2.Int64Observer, *IntCounter, int64]
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

	cpuTimeNames := attrProv.For(attributes.ProcessCPUTime)
	attrCPUTime := attributes.OpenTelemetryGetters(process.OTELGetters, cpuTimeNames)

	cpuUtilNames := attrProv.For(attributes.ProcessCPUUtilization)
	attrCPUUtil := attributes.OpenTelemetryGetters(process.OTELGetters, cpuUtilNames)

	diskNames := attrProv.For(attributes.ProcessDiskIO)
	attrDisk := attributes.OpenTelemetryGetters(process.OTELGetters, diskNames)

	mr := &procMetricsExporter{
		log:         log,
		ctx:         ctx,
		cfg:         cfg,
		clock:       expire.NewCachedClock(timeNow),
		attrCPUTime: attrCPUTime,
		attrCPUUtil: attrCPUUtil,
		attrMemory: attributes.OpenTelemetryGetters(process.OTELGetters,
			attrProv.For(attributes.ProcessMemoryUsage)),
		attrMemoryVirtual: attributes.OpenTelemetryGetters(process.OTELGetters,
			attrProv.For(attributes.ProcessMemoryVirtual)),
		attrDisk: attrDisk,
	}
	if slices.Contains(cpuTimeNames, attr2.ProcCPUState) {
		mr.cpuTimeObserver = cpuTimeDisaggregatedObserver
	} else {
		mr.cpuTimeObserver = cpuTimeAggregatedObserver
	}
	if slices.Contains(cpuUtilNames, attr2.ProcCPUState) {
		mr.cpuUtilisationObserver = cpuUtilisationDisaggregatedObserver
	} else {
		mr.cpuUtilisationObserver = cpuUtilisationAggregatedObserver
	}
	if slices.Contains(diskNames, attr2.ProcDiskIODir) {
		mr.diskObserver = diskDisaggregatedObserver
	} else {
		mr.diskObserver = diskAggregatedObserver
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

	// memory metrics are defined as UpDownCounters in the Otel specification, but we
	// internally treat them as gauges, as it's aligned to what we get from the /proc filesystem
	m.memory = NewExpirer[*process.Status, metric2.Int64Observer](
		NewIntGauge, me.attrMemory, timeNow, me.cfg.Metrics.TTL)
	if _, err := meter.Int64ObservableUpDownCounter(
		attributes.ProcessMemoryUsage.OTEL,
		metric2.WithDescription("The amount of physical memory in use"),
		metric2.WithUnit("By"),
		metric2.WithInt64Callback(m.memory.Collect),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryUsage.OTEL, "error", err)
		return nil, err
	}
	// memory metrics are defined as UpDownCounters in the Otel specification, but we
	// internally treat them as gauges, as it's aligned to what we get from the /proc filesystem
	m.memoryVirtual = NewExpirer[*process.Status, metric2.Int64Observer](
		NewIntGauge, me.attrMemory, timeNow, me.cfg.Metrics.TTL)
	if _, err := meter.Int64ObservableUpDownCounter(
		attributes.ProcessMemoryVirtual.OTEL,
		metric2.WithDescription("The amount of committed virtual memory"),
		metric2.WithUnit("By"),
		metric2.WithInt64Callback(m.memoryVirtual.Collect),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	}
	// disk metrics are defined as Counter in the Otel specification, but we
	// internally treat them as gauges, as it's aligned to what we get from the /proc filesystem
	m.disk = NewExpirer[*process.Status, metric2.Int64Observer](
		NewIntCounter, me.attrDisk, timeNow, me.cfg.Metrics.TTL)
	if _, err := meter.Int64ObservableCounter(
		attributes.ProcessDiskIO.OTEL,
		metric2.WithDescription("Disk bytes transferred"),
		metric2.WithUnit("By"),
		metric2.WithInt64Callback(m.disk.Collect),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryVirtual.OTEL, "error", err)
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
			me.observeMetric(reporter, s)
		}
	}
}

func (me *procMetricsExporter) observeMetric(reporter *procMetrics, s *process.Status) {
	me.log.Debug("reporting data for record", "record", s)

	me.cpuTimeObserver(reporter, s)
	me.cpuUtilisationObserver(reporter, s)
	reporter.memory.ForRecord(s).Set(s.MemoryRSSBytes)
	reporter.memoryVirtual.ForRecord(s).Set(s.MemoryVMSBytes)

	me.diskObserver(reporter, s)
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

func diskAggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.disk.ForRecord(record).Add(int64(record.IOReadBytesDelta + record.IOWriteBytesDelta))
}

func diskDisaggregatedObserver(reporter *procMetrics, record *process.Status) {
	reporter.disk.ForRecord(record, diskIODirRead).Add(int64(record.IOReadBytesDelta))
	reporter.disk.ForRecord(record, diskIODirWrite).Add(int64(record.IOWriteBytesDelta))
}
