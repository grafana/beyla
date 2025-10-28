package otel

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strconv"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/export/expire"
	obiotel "go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	metric2 "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/export/extraattributes"
	extranames "github.com/grafana/beyla/v2/pkg/export/extraattributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
)

var (
	stateWaitAttr   = extranames.ProcCPUMode.OTEL().String("wait")
	stateUserAttr   = extranames.ProcCPUMode.OTEL().String("user")
	stateSystemAttr = extranames.ProcCPUMode.OTEL().String("system")

	diskIODirRead  = extranames.ProcDiskIODir.OTEL().String("read")
	diskIODirWrite = extranames.ProcDiskIODir.OTEL().String("write")

	netIODirTx  = extranames.ProcNetIODir.OTEL().String("transmit")
	netIODirRcv = extranames.ProcNetIODir.OTEL().String("receive")
)

// ProcMetricsConfig extends MetricsConfig for process metrics
type ProcMetricsConfig struct {
	Metrics     *otelcfg.MetricsConfig
	SelectorCfg *attributes.SelectorConfig
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
	reporters otelcfg.ReporterPool[*process.ID, *procMetrics]

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

	procStatusInput <-chan []*process.Status
}

type procMetrics struct {
	ctx      context.Context
	provider *metric.MeterProvider

	// don't forget to add the cleanup code in cleanupAllMetricsInstances function
	cpuTime        *obiotel.Expirer[*process.Status, metric2.Float64Counter, float64]
	cpuUtilisation *obiotel.Expirer[*process.Status, metric2.Float64Gauge, float64]
	memory         *obiotel.Expirer[*process.Status, metric2.Int64UpDownCounter, int64]
	memoryVirtual  *obiotel.Expirer[*process.Status, metric2.Int64UpDownCounter, int64]
	disk           *obiotel.Expirer[*process.Status, metric2.Int64Counter, int64]
	net            *obiotel.Expirer[*process.Status, metric2.Int64Counter, int64]
}

func ProcMetricsExporterProvider(
	ctxInfo *global.ContextInfo,
	cfg *ProcMetricsConfig,
	input *msg.Queue[[]*process.Status],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.EmptyRunFunc()
		}

		if cfg.SelectorCfg.SelectionCfg == nil {
			cfg.SelectorCfg.SelectionCfg = make(attributes.Selection)
		}

		return newProcMetricsExporter(ctx, ctxInfo, cfg, input)
	}
}

func newProcMetricsExporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *ProcMetricsConfig,
	input *msg.Queue[[]*process.Status],
) (swarm.RunFunc, error) {
	otelcfg.SetupInternalOTELSDKLogger(cfg.Metrics.SDKLogLevel)

	log := pmlog()
	log.Debug("instantiating process metrics exporter provider")

	// only user-provided attributes (or default set) will decorate the metrics
	attrProv, err := extraattributes.NewBeylaAttrSelector(ctxInfo.MetricAttributeGroups, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("process OTEL exporter attributes: %w", err)
	}

	cpuTimeNames := attrProv.For(extraattributes.ProcessCPUTime)
	attrCPUTime := attributes.OpenTelemetryGetters(process.OTELGetters, cpuTimeNames)

	cpuUtilNames := attrProv.For(extraattributes.ProcessCPUUtilization)
	attrCPUUtil := attributes.OpenTelemetryGetters(process.OTELGetters, cpuUtilNames)

	diskNames := attrProv.For(extraattributes.ProcessDiskIO)
	attrDisk := attributes.OpenTelemetryGetters(process.OTELGetters, diskNames)

	netNames := attrProv.For(extraattributes.ProcessNetIO)
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
			attrProv.For(extraattributes.ProcessMemoryUsage)),
		attrMemoryVirtual: attributes.OpenTelemetryGetters(process.OTELGetters,
			attrProv.For(extraattributes.ProcessMemoryVirtual)),
		attrDisk:        attrDisk,
		attrNet:         attrNet,
		procStatusInput: input.Subscribe(msg.SubscriberName("procStatusInput")),
	}
	if slices.Contains(cpuTimeNames, extranames.ProcCPUMode) {
		mr.cpuTimeObserver = cpuTimeDisaggregatedObserver
	} else {
		mr.cpuTimeObserver = cpuTimeAggregatedObserver
	}
	if slices.Contains(cpuUtilNames, extranames.ProcCPUMode) {
		mr.cpuUtilisationObserver = cpuUtilisationDisaggregatedObserver
	} else {
		mr.cpuUtilisationObserver = cpuUtilisationAggregatedObserver
	}
	if slices.Contains(diskNames, extranames.ProcDiskIODir) {
		mr.diskObserver = diskDisaggregatedObserver
	} else {
		mr.diskObserver = diskAggregatedObserver
	}
	if slices.Contains(netNames, extranames.ProcNetIODir) {
		mr.netObserver = netDisaggregatedObserver
	} else {
		mr.netObserver = netAggregatedObserver
	}

	mr.reporters = otelcfg.NewReporterPool[*process.ID, *procMetrics](cfg.Metrics.ReportersCacheLen, cfg.Metrics.TTL, timeNow,
		func(id svc.UID, v *procMetrics) {
			llog := log.With("service", id)
			llog.Debug("evicting metrics reporter from cache")
			v.cleanupAllMetricsInstances()
			go func() {
				if err := v.provider.ForceFlush(ctx); err != nil {
					llog.Warn("error flushing evicted metrics provider", "error", err)
				}
			}()
		}, mr.newMetricSet)

	mr.exporter, err = ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		log.Error("instantiating metrics exporter", "error", err)
		return nil, err
	}

	return mr.Do, nil
}

// getFilteredProcessResourceAttrs returns resource attributes filtered based on the attribute selector
// for process metrics.
func getFilteredProcessResourceAttrs(hostID string, procID *process.ID, attrSelector attributes.Selection) []attribute.KeyValue {
	baseAttrs := otelcfg.GetResourceAttrs(hostID, procID.Service)
	procAttrs := []attribute.KeyValue{
		semconv.ServiceInstanceID(procID.UID.Instance),
		extranames.ProcCommand.OTEL().String(procID.Command),
		extranames.ProcOwner.OTEL().String(procID.User),
		extranames.ProcParentPid.OTEL().String(strconv.Itoa(int(procID.ParentProcessID))),
		extranames.ProcPid.OTEL().String(strconv.Itoa(int(procID.ProcessID))),
		extranames.ProcCommandLine.OTEL().String(procID.CommandLine),
		extranames.ProcCommandArgs.OTEL().StringSlice(procID.CommandArgs),
		extranames.ProcExecName.OTEL().String(procID.ExecName),
		extranames.ProcExecPath.OTEL().String(procID.ExecPath),
	}
	return otelcfg.GetFilteredAttributesByPrefix(baseAttrs, attrSelector, procAttrs, []string{"process."})
}

func (me *procMetricsExporter) newMetricSet(procID *process.ID) (*procMetrics, error) {
	log := me.log.With("service", procID.Service, "processID", procID.UID)
	log.Debug("creating new Metrics exporter")
	resources := resource.NewWithAttributes(semconv.SchemaURL, getFilteredProcessResourceAttrs(me.hostID, procID, me.cfg.SelectorCfg.SelectionCfg)...)
	opts := []metric.Option{
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(me.exporter,
			metric.WithInterval(me.cfg.Metrics.Interval))),
	}

	m := procMetrics{
		ctx:      me.ctx,
		provider: metric.NewMeterProvider(opts...),
	}

	meter := m.provider.Meter(ReporterName)

	if cpuTime, err := meter.Float64Counter(
		extraattributes.ProcessCPUTime.OTEL, metric2.WithUnit("s"),
		metric2.WithDescription("Total CPU seconds broken down by different states"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	} else {
		m.cpuTime = obiotel.NewExpirer[*process.Status, metric2.Float64Counter, float64](
			me.ctx, cpuTime, me.attrCPUTime, timeNow, me.cfg.Metrics.TTL)
	}

	if cpuUtilisation, err := meter.Float64Gauge(
		extraattributes.ProcessCPUUtilization.OTEL,
		metric2.WithDescription("Difference in process.cpu.time since the last measurement, divided by the elapsed time and number of CPUs available to the process"),
		metric2.WithUnit("1"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessCPUUtilization.OTEL, "error", err)
		return nil, err
	} else {
		m.cpuUtilisation = obiotel.NewExpirer[*process.Status, metric2.Float64Gauge, float64](
			me.ctx, cpuUtilisation, me.attrCPUUtil, timeNow, me.cfg.Metrics.TTL)
	}

	// memory metrics are defined as UpDownCounters in the Otel specification, but we
	// internally treat them as gauges, as it's aligned to what we get from the /proc filesystem

	if memory, err := meter.Int64UpDownCounter(
		extraattributes.ProcessMemoryUsage.OTEL,
		metric2.WithDescription("The amount of physical memory in use"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessMemoryUsage.OTEL, "error", err)
		return nil, err
	} else {
		m.memory = obiotel.NewExpirer[*process.Status, metric2.Int64UpDownCounter, int64](
			me.ctx, memory, me.attrMemory, timeNow, me.cfg.Metrics.TTL)
	}

	if memoryVirtual, err := meter.Int64UpDownCounter(
		extraattributes.ProcessMemoryVirtual.OTEL,
		metric2.WithDescription("The amount of committed virtual memory"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.memoryVirtual = obiotel.NewExpirer[*process.Status, metric2.Int64UpDownCounter, int64](
			me.ctx, memoryVirtual, me.attrMemoryVirtual, timeNow, me.cfg.Metrics.TTL)
	}

	if disk, err := meter.Int64Counter(
		extraattributes.ProcessDiskIO.OTEL,
		metric2.WithDescription("Disk bytes transferred"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.disk = obiotel.NewExpirer[*process.Status, metric2.Int64Counter, int64](
			me.ctx, disk, me.attrDisk, timeNow, me.cfg.Metrics.TTL)
	}

	if net, err := meter.Int64Counter(
		extraattributes.ProcessNetIO.OTEL,
		metric2.WithDescription("Network bytes transferred"),
		metric2.WithUnit("By"),
	); err != nil {
		log.Error("creating observable gauge for "+extraattributes.ProcessMemoryVirtual.OTEL, "error", err)
		return nil, err
	} else {
		m.net = obiotel.NewExpirer[*process.Status, metric2.Int64Counter, int64](
			me.ctx, net, me.attrNet, timeNow, me.cfg.Metrics.TTL)
	}
	return &m, nil
}

// Do reads all the process status data points and create the metrics accordingly
func (me *procMetricsExporter) Do(_ context.Context) {
	for i := range me.procStatusInput {
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
