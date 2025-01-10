package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"github.com/mariomac/pipes/pipe"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/export/attributes"
	attr2 "github.com/grafana/beyla/pkg/export/attributes/names"
	"github.com/grafana/beyla/pkg/export/expire"
	"github.com/grafana/beyla/pkg/export/otel/metric"
	metric2 "github.com/grafana/beyla/pkg/export/otel/metric/api/metric"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/svc"
)

var (
	stateWaitAttr   = attr2.ProcCPUMode.OTEL().String("wait")
	stateUserAttr   = attr2.ProcCPUMode.OTEL().String("user")
	stateSystemAttr = attr2.ProcCPUMode.OTEL().String("system")

	diskIODirRead  = attr2.ProcDiskIODir.OTEL().String("read")
	diskIODirWrite = attr2.ProcDiskIODir.OTEL().String("write")

	netIODirTx  = attr2.ProcNetIODir.OTEL().String("transmit")
	netIODirRcv = attr2.ProcNetIODir.OTEL().String("receive")
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

	hostID string

	exporter  sdkmetric.Exporter
	reporters ReporterPool[*process.ID, *procMetrics]

	log *slog.Logger

	attrCPUTime       []attributes.Field[*process.Status, attribute.KeyValue]
	attrCPUUtil       []attributes.Field[*process.Status, attribute.KeyValue]
	attrMemory        []attributes.Field[*process.Status, attribute.KeyValue]
	attrMemoryVirtual []attributes.Field[*process.Status, attribute.KeyValue]
	attrDisk          []attributes.Field[*process.Status, attribute.KeyValue]
	attrNet           []attributes.Field[*process.Status, attribute.KeyValue]

	// the observation code for CPU metrics will be different depending on
	// the "cpu.mode" attribute being selected or not
	cpuTimeObserver        func(context.Context, *procMetrics, *process.Status)
	cpuUtilisationObserver func(context.Context, *procMetrics, *process.Status)

	// the observation code for disk and network metrics will be different depending on
	// the *.io.direction attributes being selected or not
	diskObserver func(context.Context, *procMetrics, *process.Status)
	netObserver  func(context.Context, *procMetrics, *process.Status)
}

type procMetrics struct {
	ctx      context.Context
	provider *metric.MeterProvider

	// don't forget to add the cleanup code in cleanupAllMetricsInstances function
	cpuTime        *Expirer[*process.Status, metric2.Float64Counter, float64]
	cpuUtilisation *Expirer[*process.Status, metric2.Float64Gauge, float64]
	memory         *Expirer[*process.Status, metric2.Int64UpDownCounter, int64]
	memoryVirtual  *Expirer[*process.Status, metric2.Int64UpDownCounter, int64]
	disk           *Expirer[*process.Status, metric2.Int64Counter, int64]
	net            *Expirer[*process.Status, metric2.Int64Counter, int64]
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

	netNames := attrProv.For(attributes.ProcessNetIO)
	attrNet := attributes.OpenTelemetryGetters(process.OTELGetters, netNames)

	mr := &procMetricsExporter{
		log:         log,
		ctx:         ctx,
		cfg:         cfg,
		hostID:      ctxInfo.HostID,
		clock:       expire.NewCachedClock(timeNow),
		attrCPUTime: attrCPUTime,
		attrCPUUtil: attrCPUUtil,
		attrMemory: attributes.OpenTelemetryGetters(process.OTELGetters,
			attrProv.For(attributes.ProcessMemoryUsage)),
		attrMemoryVirtual: attributes.OpenTelemetryGetters(process.OTELGetters,
			attrProv.For(attributes.ProcessMemoryVirtual)),
		attrDisk: attrDisk,
		attrNet:  attrNet,
	}
	if slices.Contains(cpuTimeNames, attr2.ProcCPUMode) {
		mr.cpuTimeObserver = cpuTimeDisaggregatedObserver
	} else {
		mr.cpuTimeObserver = cpuTimeAggregatedObserver
	}
	if slices.Contains(cpuUtilNames, attr2.ProcCPUMode) {
		mr.cpuUtilisationObserver = cpuUtilisationDisaggregatedObserver
	} else {
		mr.cpuUtilisationObserver = cpuUtilisationAggregatedObserver
	}
	if slices.Contains(diskNames, attr2.ProcDiskIODir) {
		mr.diskObserver = diskDisaggregatedObserver
	} else {
		mr.diskObserver = diskAggregatedObserver
	}
	if slices.Contains(netNames, attr2.ProcNetIODir) {
		mr.netObserver = netDisaggregatedObserver
	} else {
		mr.netObserver = netAggregatedObserver
	}

	mr.reporters = NewReporterPool[*process.ID, *procMetrics](cfg.Metrics.ReportersCacheLen, cfg.Metrics.TTL, timeNow,
		func(id svc.UID, v *expirable[*procMetrics]) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.value.cleanupAllMetricsInstances()
			go func() {
				if err := v.value.provider.ForceFlush(ctx); err != nil {
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

func getProcessResourceAttrs(hostID string, procID *process.ID) []attribute.KeyValue {
	return append(
		getResourceAttrs(hostID, procID.Service),
		semconv.ServiceInstanceID(procID.UID.Instance),
		attr2.ProcCommand.OTEL().String(procID.Command),
		attr2.ProcOwner.OTEL().String(procID.User),
		attr2.ProcParentPid.OTEL().String(strconv.Itoa(int(procID.ParentProcessID))),
		attr2.ProcPid.OTEL().String(strconv.Itoa(int(procID.ProcessID))),
		attr2.ProcCommandLine.OTEL().String(procID.CommandLine),
		attr2.ProcCommandArgs.OTEL().StringSlice(procID.CommandArgs),
		attr2.ProcExecName.OTEL().String(procID.ExecName),
		attr2.ProcExecPath.OTEL().String(procID.ExecPath),
	)
}

func (me *procMetricsExporter) newMetricSet(procID *process.ID) (*procMetrics, error) {
	log := me.log.With("service", procID.Service, "processID", procID.UID)
	log.Debug("creating new Metrics exporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, getProcessResourceAttrs(me.hostID, procID)...)
	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(me.exporter,
			metric.WithInterval(me.cfg.Metrics.Interval))),
	}

	m := procMetrics{
		ctx:      me.ctx,
		provider: metric.NewMeterProvider(opts...),
	}

	meter := m.provider.Meter(reporterName)

	if cpuTime, err := meter.Float64Counter(
		attributes.ProcessCPUTime.OTEL, metric2.WithUnit("s"),
		metric2.WithDescription("Total CPU seconds broken down by different states"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	} else {
		m.cpuTime = NewExpirer[*process.Status, metric2.Float64Counter, float64](
			me.ctx, cpuTime, me.attrCPUTime, timeNow, me.cfg.Metrics.TTL)
	}

	if cpuUtilisation, err := meter.Float64Gauge(
		attributes.ProcessCPUUtilization.OTEL,
		metric2.WithDescription("Difference in process.cpu.time since the last measurement, divided by the elapsed time and number of CPUs available to the process"),
		metric2.WithUnit("1"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	} else {
		m.cpuUtilisation = NewExpirer[*process.Status, metric2.Float64Gauge, float64](
			me.ctx, cpuUtilisation, me.attrCPUUtil, timeNow, me.cfg.Metrics.TTL)
	}

	// memory metrics are defined as UpDownCounters in the Otel specification, but we
	// internally treat them as gauges, as it's aligned to what we get from the /proc filesystem

	if memory, err := meter.Int64UpDownCounter(
		attributes.ProcessMemoryUsage.OTEL,
		metric2.WithDescription("The amount of physical memory in use"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryUsage.OTEL, "error", err)
		return nil, err
	} else {
		m.memory = NewExpirer[*process.Status, metric2.Int64UpDownCounter, int64](
			me.ctx, memory, me.attrMemory, timeNow, me.cfg.Metrics.TTL)
	}

	if memoryVirtual, err := meter.Int64UpDownCounter(
		attributes.ProcessMemoryVirtual.OTEL,
		metric2.WithDescription("The amount of committed virtual memory"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.memoryVirtual = NewExpirer[*process.Status, metric2.Int64UpDownCounter, int64](
			me.ctx, memoryVirtual, me.attrMemoryVirtual, timeNow, me.cfg.Metrics.TTL)
	}

	if disk, err := meter.Int64Counter(
		attributes.ProcessDiskIO.OTEL,
		metric2.WithDescription("Disk bytes transferred"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.disk = NewExpirer[*process.Status, metric2.Int64Counter, int64](
			me.ctx, disk, me.attrDisk, timeNow, me.cfg.Metrics.TTL)
	}

	if net, err := meter.Int64Counter(
		attributes.ProcessNetIO.OTEL,
		metric2.WithDescription("Network bytes transferred"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+attributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.net = NewExpirer[*process.Status, metric2.Int64Counter, int64](
			me.ctx, net, me.attrNet, timeNow, me.cfg.Metrics.TTL)
	}
	return &m, nil
}

// Do reads all the process status data points and create the metrics accordingly
func (me *procMetricsExporter) Do(in <-chan []*process.Status) {
	for i := range in {
		me.clock.Update()
		for _, s := range i {
			reporter, err := me.reporters.For(&s.ID)
			if err != nil {
				me.log.Error("unexpected error creating OTEL resource. Ignoring metric",
					"error", err, "service", s.ID.Service)
				continue
			}
			me.observeMetric(reporter, s)
		}
	}
}

func (me *procMetricsExporter) observeMetric(reporter *procMetrics, s *process.Status) {
	me.cpuTimeObserver(me.ctx, reporter, s)
	me.cpuUtilisationObserver(me.ctx, reporter, s)

	mem, attrs := reporter.memory.ForRecord(s)
	mem.Add(me.ctx, s.MemoryRSSBytesDelta, metric2.WithAttributeSet(attrs))

	vmem, attrs := reporter.memoryVirtual.ForRecord(s)
	vmem.Add(me.ctx, s.MemoryVMSBytesDelta, metric2.WithAttributeSet(attrs))

	me.diskObserver(me.ctx, reporter, s)
	me.netObserver(me.ctx, reporter, s)
}

// aggregated observers report all the CPU metrics in a single data point
// to be triggered when the user disables the "cpu_mode" metric
func cpuTimeAggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	cpu, attrs := reporter.cpuTime.ForRecord(record)
	cpu.Add(ctx, record.CPUTimeUserDelta+record.CPUTimeSystemDelta+record.CPUTimeWaitDelta,
		metric2.WithAttributeSet(attrs))
}

func cpuUtilisationAggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	cpu, attrs := reporter.cpuUtilisation.ForRecord(record)
	cpu.Record(ctx, record.CPUUtilisationUser+record.CPUUtilisationSystem+record.CPUUtilisationWait,
		metric2.WithAttributeSet(attrs))
}

// disaggregated observers report three CPU metrics: system, user and wait time
// to be triggered when the user enables the "cpu_mode" metric
func cpuTimeDisaggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	cpu, attrs := reporter.cpuTime.ForRecord(record, stateWaitAttr)
	cpu.Add(ctx, record.CPUTimeWaitDelta, metric2.WithAttributeSet(attrs))
	cpu, attrs = reporter.cpuTime.ForRecord(record, stateUserAttr)
	cpu.Add(ctx, record.CPUTimeUserDelta, metric2.WithAttributeSet(attrs))
	cpu, attrs = reporter.cpuTime.ForRecord(record, stateSystemAttr)
	cpu.Add(ctx, record.CPUTimeSystemDelta, metric2.WithAttributeSet(attrs))
}

func cpuUtilisationDisaggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	cpu, attrs := reporter.cpuUtilisation.ForRecord(record, stateWaitAttr)
	cpu.Record(ctx, record.CPUUtilisationWait, metric2.WithAttributeSet(attrs))
	cpu, attrs = reporter.cpuUtilisation.ForRecord(record, stateUserAttr)
	cpu.Record(ctx, record.CPUUtilisationUser, metric2.WithAttributeSet(attrs))
	cpu, attrs = reporter.cpuUtilisation.ForRecord(record, stateSystemAttr)
	cpu.Record(ctx, record.CPUUtilisationSystem, metric2.WithAttributeSet(attrs))
}

func diskAggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	disk, attrs := reporter.disk.ForRecord(record)
	disk.Add(ctx, int64(record.IOReadBytesDelta+record.IOWriteBytesDelta), metric2.WithAttributeSet(attrs))
}

func diskDisaggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	disk, attrs := reporter.disk.ForRecord(record, diskIODirRead)
	disk.Add(ctx, int64(record.IOReadBytesDelta), metric2.WithAttributeSet(attrs))
	disk, attrs = reporter.disk.ForRecord(record, diskIODirWrite)
	disk.Add(ctx, int64(record.IOWriteBytesDelta), metric2.WithAttributeSet(attrs))
}

func netAggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	net, attrs := reporter.net.ForRecord(record)
	net.Add(ctx, record.NetTxBytesDelta+record.NetRcvBytesDelta, metric2.WithAttributeSet(attrs))
}

func netDisaggregatedObserver(ctx context.Context, reporter *procMetrics, record *process.Status) {
	net, attrs := reporter.net.ForRecord(record, netIODirTx)
	net.Add(ctx, record.NetTxBytesDelta, metric2.WithAttributeSet(attrs))
	net, attrs = reporter.net.ForRecord(record, netIODirRcv)
	net.Add(ctx, record.NetRcvBytesDelta, metric2.WithAttributeSet(attrs))
}

func (r *procMetrics) cleanupAllMetricsInstances() {
	r.cpuTime.RemoveAllMetrics(r.ctx)
	r.cpuUtilisation.RemoveAllMetrics(r.ctx)
	r.memory.RemoveAllMetrics(r.ctx)
	r.memoryVirtual.RemoveAllMetrics(r.ctx)
	r.disk.RemoveAllMetrics(r.ctx)
	r.net.RemoveAllMetrics(r.ctx)
}
