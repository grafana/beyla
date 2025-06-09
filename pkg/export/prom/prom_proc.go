package prom

import (
	"context"
	"fmt"
	"slices"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/v2/pkg/export/attributes"
	attr2 "github.com/grafana/beyla/v2/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/export/expire"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/internal/connector"
	"github.com/grafana/beyla/v2/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
)

// injectable function reference for testing

// ProcPrometheusConfig for process metrics just wraps the global prom.ProcPrometheusConfig as provided by the user
type ProcPrometheusConfig struct {
	Metrics     *PrometheusConfig
	SelectorCfg *attributes.SelectorConfig
}

// nolint:gocritic
func (p ProcPrometheusConfig) Enabled() bool {
	return p.Metrics != nil && (p.Metrics.Port != 0 || p.Metrics.Registry != nil) && p.Metrics.OTelMetricsEnabled() &&
		slices.Contains(p.Metrics.Features, otel.FeatureProcess)
}

// ProcPrometheusEndpoint provides a pipeline node that export the process information as
// prometheus metrics
func ProcPrometheusEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *ProcPrometheusConfig,
	procStatusInput *msg.Queue[[]*process.Status],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return swarm.EmptyRunFunc()
		}
		reporter, err := newProcReporter(ctxInfo, cfg, procStatusInput)
		if err != nil {
			return nil, err
		}
		if cfg.Metrics.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

type procMetricsReporter struct {
	cfg *PrometheusConfig

	promConnect *connector.PrometheusManager

	clock *expire.CachedClock

	// metrics
	cpuTimeAttrs []attributes.Field[*process.Status, string]
	cpuTime      *Expirer[prometheus.Counter]

	cpuUtilizationAttrs []attributes.Field[*process.Status, string]
	cpuUtilization      *Expirer[prometheus.Gauge]

	// the OTEL spec for process memory says that this type is an UpDownCounter.
	// Using Gauge as the nearest type in Prometheus.
	memoryAttrs []attributes.Field[*process.Status, string]
	memory      *Expirer[prometheus.Gauge]

	memoryVirtualAttrs []attributes.Field[*process.Status, string]
	memoryVirtual      *Expirer[prometheus.Gauge]

	diskAttrs []attributes.Field[*process.Status, string]
	disk      *Expirer[prometheus.Counter]

	netAttrs []attributes.Field[*process.Status, string]
	net      *Expirer[prometheus.Counter]

	// the observation code for CPU metrics will be different depending on
	// the "cpu.mode" attribute being selected or not
	cpuTimeObserver        func(*process.Status)
	cpuUtilizationObserver func(*process.Status)

	// the observation code for IO metrics will be different depending on
	// the "*.io.direction" attributes
	diskObserver    func(*process.Status)
	netObserver     func(*process.Status)
	procStatusInput <-chan []*process.Status
}

func newProcReporter(ctxInfo *global.ContextInfo, cfg *ProcPrometheusConfig, input *msg.Queue[[]*process.Status]) (*procMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.SelectorCfg)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	cpuTimeLblNames, cpuTimeGetters, cpuTimeHasState :=
		attributesWithExplicit(provider, attributes.ProcessCPUTime, attr2.ProcCPUMode)
	cpuUtilLblNames, cpuUtilGetters, cpuUtilHasState :=
		attributesWithExplicit(provider, attributes.ProcessCPUUtilization, attr2.ProcCPUMode)
	diskLblNames, diskGetters, diskHasDirection :=
		attributesWithExplicit(provider, attributes.ProcessDiskIO, attr2.ProcDiskIODir)
	netLblNames, netGetters, netHasDirection :=
		attributesWithExplicit(provider, attributes.ProcessDiskIO, attr2.ProcNetIODir)

	attrMemory := attributes.PrometheusGetters(process.PromGetters, provider.For(attributes.ProcessMemoryUsage))
	attrMemoryVirtual := attributes.PrometheusGetters(process.PromGetters, provider.For(attributes.ProcessMemoryVirtual))

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &procMetricsReporter{
		cfg:          cfg.Metrics,
		promConnect:  ctxInfo.Prometheus,
		clock:        clock,
		cpuTimeAttrs: cpuTimeGetters,
		cpuTime: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.ProcessCPUTime.Prom,
			Help: "Total CPU seconds broken down by different states",
		}, cpuTimeLblNames).MetricVec, clock.Time, cfg.Metrics.TTL),
		cpuUtilizationAttrs: cpuUtilGetters,
		cpuUtilization: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.ProcessCPUUtilization.Prom,
			Help: "Difference in process.cpu.time since the last measurement, divided by the elapsed time and number of CPUs available to the process",
		}, cpuUtilLblNames).MetricVec, clock.Time, cfg.Metrics.TTL),
		memoryAttrs: attrMemory,
		memory: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.ProcessMemoryUsage.Prom,
			Help: "The amount of physical memory in use",
		}, labelNames(attrMemory)).MetricVec, clock.Time, cfg.Metrics.TTL),
		memoryVirtualAttrs: attrMemoryVirtual,
		memoryVirtual: NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.ProcessMemoryVirtual.Prom,
			Help: "The amount of committed virtual memory",
		}, labelNames(attrMemoryVirtual)).MetricVec, clock.Time, cfg.Metrics.TTL),
		diskAttrs: diskGetters,
		disk: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.ProcessDiskIO.Prom,
			Help: "Disk bytes transferred",
		}, diskLblNames).MetricVec, clock.Time, cfg.Metrics.TTL),
		netAttrs: netGetters,
		net: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.ProcessNetIO.Prom,
			Help: "Network bytes transferred",
		}, netLblNames).MetricVec, clock.Time, cfg.Metrics.TTL),
		procStatusInput: input.Subscribe(),
	}

	if cpuTimeHasState {
		mr.cpuTimeObserver = mr.observeDisaggregatedCPUTime
	} else {
		mr.cpuTimeObserver = mr.observeAggregatedCPUTime
	}
	if cpuUtilHasState {
		mr.cpuUtilizationObserver = mr.observeDisaggregatedCPUUtilization
	} else {
		mr.cpuUtilizationObserver = mr.observeAggregatedCPUUtilization
	}
	if diskHasDirection {
		mr.diskObserver = mr.observeDisaggregatedDisk
	} else {
		mr.diskObserver = mr.observeAggregatedDisk
	}
	if netHasDirection {
		mr.netObserver = mr.observeDisaggregatedNet
	} else {
		mr.netObserver = mr.observeAggregatedNet
	}

	if cfg.Metrics.Registry != nil {
		cfg.Metrics.Registry.MustRegister(
			mr.cpuUtilization, mr.cpuTime,
			mr.memory, mr.memoryVirtual,
			mr.disk, mr.net,
		)
	} else {
		mr.promConnect.Register(cfg.Metrics.Port, cfg.Metrics.Path,
			mr.cpuUtilization, mr.cpuTime,
			mr.memory, mr.memoryVirtual,
			mr.disk,
			mr.net)
	}

	return mr, nil
}

func (r *procMetricsReporter) reportMetrics(ctx context.Context) {
	go r.promConnect.StartHTTP(ctx)
	r.collectMetrics(ctx)
}

func (r *procMetricsReporter) collectMetrics(_ context.Context) {
	for processes := range r.procStatusInput {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, proc := range processes {
			r.observeMetric(proc)
		}
	}
}

func (r *procMetricsReporter) observeMetric(proc *process.Status) {
	r.cpuTimeObserver(proc)
	r.cpuUtilizationObserver(proc)
	r.memory.WithLabelValues(labelValues(proc, r.memoryAttrs)...).
		metric.Set(float64(proc.MemoryRSSBytes))
	r.memoryVirtual.WithLabelValues(labelValues(proc, r.memoryVirtualAttrs)...).
		metric.Set(float64(proc.MemoryVMSBytes))
	r.diskObserver(proc)
	r.netObserver(proc)
}

// aggregated observers report all the CPU metrics in a single data point
// to be triggered when the user disables the "cpu_mode" metric
func (r *procMetricsReporter) observeAggregatedCPUTime(proc *process.Status) {
	r.cpuTime.WithLabelValues(labelValues(proc, r.cpuTimeAttrs)...).
		metric.Add(proc.CPUTimeUserDelta + proc.CPUTimeSystemDelta + proc.CPUTimeWaitDelta)
}

func (r *procMetricsReporter) observeAggregatedCPUUtilization(proc *process.Status) {
	r.cpuUtilization.WithLabelValues(labelValues(proc, r.cpuUtilizationAttrs)...).
		metric.Set(proc.CPUUtilisationUser + proc.CPUUtilisationSystem + proc.CPUUtilisationWait)
}

// disaggregated observers report three CPU metrics: system, user and wait time
// to be triggered when the user enables the "cpu_mode" metric
func (r *procMetricsReporter) observeDisaggregatedCPUTime(proc *process.Status) {
	commonLabelValues := labelValues(proc, r.cpuTimeAttrs)

	userLabels := append([]string{"user"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(userLabels...).metric.Add(proc.CPUTimeUserDelta)

	systemLabels := append([]string{"system"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(systemLabels...).metric.Add(proc.CPUTimeSystemDelta)

	waitLabels := append([]string{"wait"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(waitLabels...).metric.Add(proc.CPUTimeWaitDelta)
}

func (r *procMetricsReporter) observeDisaggregatedCPUUtilization(proc *process.Status) {
	commonLabelValues := labelValues(proc, r.cpuUtilizationAttrs)

	userLabels := append([]string{"user"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(userLabels...).metric.Set(proc.CPUUtilisationUser)

	systemLabels := append([]string{"system"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(systemLabels...).metric.Set(proc.CPUUtilisationSystem)

	waitLabels := append([]string{"wait"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(waitLabels...).metric.Set(proc.CPUUtilisationWait)
}

func (r *procMetricsReporter) observeAggregatedDisk(proc *process.Status) {
	r.disk.WithLabelValues(labelValues(proc, r.diskAttrs)...).
		metric.Add(float64(proc.IOReadBytesDelta + proc.IOWriteBytesDelta))
}

func (r *procMetricsReporter) observeDisaggregatedDisk(proc *process.Status) {
	commonLabels := labelValues(proc, r.diskAttrs)
	readLabels := append([]string{"read"}, commonLabels...)
	r.disk.WithLabelValues(readLabels...).metric.Add(float64(proc.IOReadBytesDelta))
	writeLabels := append([]string{"write"}, commonLabels...)
	r.disk.WithLabelValues(writeLabels...).metric.Add(float64(proc.IOWriteBytesDelta))
}

func (r *procMetricsReporter) observeAggregatedNet(proc *process.Status) {
	r.net.WithLabelValues(labelValues(proc, r.netAttrs)...).
		metric.Add(float64(proc.NetTxBytesDelta + proc.NetRcvBytesDelta))
}

func (r *procMetricsReporter) observeDisaggregatedNet(proc *process.Status) {
	commonLabels := labelValues(proc, r.netAttrs)
	readLabels := append([]string{"transmit"}, commonLabels...)
	r.net.WithLabelValues(readLabels...).metric.Add(float64(proc.NetTxBytesDelta))
	writeLabels := append([]string{"receive"}, commonLabels...)
	r.net.WithLabelValues(writeLabels...).metric.Add(float64(proc.NetRcvBytesDelta))
}

// attributesWithExplicit returns, for a metric name definition,
// which attribute names are defined as well as the getters for
// them. It also returns if the invoker must explicitly add the
// provided explicit attribute name and value (e.g. "cpu.mode"
// or "disk.io.direction")
func attributesWithExplicit(
	provider *attributes.AttrSelector, metricName attributes.Name, explicitAttribute attr2.Name,
) (
	names []string, getters []attributes.Field[*process.Status, string], containsExplicit bool,
) {
	attrNames := provider.For(metricName)
	// For example, "cpu_mode" won't be added by PrometheusGetters, as it's not defined in the *process.Status
	// we need to be aware of the user willing to add it to explicitly choose between
	// observeAggregatedCPU and observeDisaggregatedCPU
	// Similar for "process_disk_io" or "process_network_io"
	containsExplicit = slices.Contains(attrNames, explicitAttribute)
	getters = attributes.PrometheusGetters(process.PromGetters, attrNames)

	if containsExplicit {
		// the names and the getters arrays will have different length.
		// For example, the metric value setter function of the will have to prepend
		// the attribute value as first value in their attributes list
		// (e.g. wait/system/user in CPU metrics or write/read in IO metrics)
		names = []string{explicitAttribute.Prom()}
	}
	for _, label := range getters {
		names = append(names, label.ExposedName)
	}
	return
}
