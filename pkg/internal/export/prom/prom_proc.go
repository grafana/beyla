package prom

import (
	"context"
	"fmt"
	"slices"

	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr2 "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/export/expire"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
)

// injectable function reference for testing

// ProcPrometheusConfig for process metrics just wraps the global prom.ProcPrometheusConfig as provided by the user
type ProcPrometheusConfig struct {
	Metrics            *PrometheusConfig
	AttributeSelectors attributes.Selection
}

// nolint:gocritic
func (p ProcPrometheusConfig) Enabled() bool {
	// TODO:
	return p.Metrics != nil && p.Metrics.Port != 0 && p.Metrics.OTelMetricsEnabled() &&
		slices.Contains(p.Metrics.Features, otel.FeatureProcess)
}

// ProcPrometheusEndpoint provides a pipeline node that export the process information as
// prometheus metrics
func ProcPrometheusEndpoint(
	ctx context.Context, ctxInfo *global.ContextInfo, cfg *ProcPrometheusConfig,
) pipe.FinalProvider[[]*process.Status] {
	return func() (pipe.FinalFunc[[]*process.Status], error) {
		if !cfg.Enabled() {
			// This node is not going to be instantiated. Let the pipes library just ignore it.
			return pipe.IgnoreFinal[[]*process.Status](), nil
		}
		reporter, err := newProcReporter(ctx, ctxInfo, cfg)
		if err != nil {
			return nil, err
		}
		return reporter.reportMetrics, nil
	}
}

type procMetricsReporter struct {
	cfg *PrometheusConfig

	promConnect *connector.PrometheusManager

	clock *expire.CachedClock
	bgCtx context.Context

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

	// the observation code for CPU metrics will be different depending on
	// the "process.cpu.state" attribute being selected or not
	cpuTimeObserver        func([]string, *process.Status)
	cpuUtilizationObserver func([]string, *process.Status)
}

func newProcReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *ProcPrometheusConfig,
) (*procMetricsReporter, error) {
	group := ctxInfo.MetricAttributeGroups
	// this property can't be set inside the ConfiguredGroups function, otherwise the
	// OTEL exporter would report also some prometheus-exclusive attributes
	group.Add(attributes.GroupPrometheus)

	provider, err := attributes.NewAttrSelector(group, cfg.AttributeSelectors)
	if err != nil {
		return nil, fmt.Errorf("network Prometheus exporter attributes enable: %w", err)
	}

	cpuTimeLblNames, cpuTimeGetters, cpuTimeHasState := cpuAttributes(provider, attributes.ProcessCPUTime)
	cpuUtilLblNames, cpuUtilGetters, cpuUtilHasState := cpuAttributes(provider, attributes.ProcessCPUUtilization)

	attrMemory := attributes.PrometheusGetters(process.PromGetters, provider.For(attributes.ProcessMemoryUsage))
	attrMemoryVirtual := attributes.PrometheusGetters(process.PromGetters, provider.For(attributes.ProcessMemoryVirtual))

	clock := expire.NewCachedClock(timeNow)
	// If service name is not explicitly set, we take the service name as set by the
	// executable inspector
	mr := &procMetricsReporter{
		bgCtx:        ctx,
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

	mr.promConnect.Register(cfg.Metrics.Port, cfg.Metrics.Path,
		mr.cpuUtilization, mr.cpuTime,
		mr.memory, mr.memoryVirtual)

	return mr, nil
}

func (r *procMetricsReporter) reportMetrics(input <-chan []*process.Status) {
	go r.promConnect.StartHTTP(r.bgCtx)
	for processes := range input {
		// clock needs to be updated to let the expirer
		// remove the old metrics
		r.clock.Update()
		for _, proc := range processes {
			r.observeMetric(proc)
		}
	}
}

func (r *procMetricsReporter) observeMetric(proc *process.Status) {
	r.cpuTimeObserver(labelValues(proc, r.cpuTimeAttrs), proc)
	r.cpuUtilizationObserver(labelValues(proc, r.cpuUtilizationAttrs), proc)
	r.memory.WithLabelValues(labelValues(proc, r.memoryAttrs)...).
		Set(float64(proc.MemoryRSSBytes))
	r.memoryVirtual.WithLabelValues(labelValues(proc, r.memoryVirtualAttrs)...).
		Set(float64(proc.MemoryVMSBytes))
}

// aggregated observers report all the CPU metrics in a single data point
// to be triggered when the user disables the "process_cpu_state" metric
func (r *procMetricsReporter) observeAggregatedCPUTime(commonLabelValues []string, flow *process.Status) {
	r.cpuTime.WithLabelValues(commonLabelValues...).
		Add(flow.CPUTimeUserDelta + flow.CPUTimeSystemDelta + flow.CPUTimeWaitDelta)
}

func (r *procMetricsReporter) observeAggregatedCPUUtilization(commonLabelValues []string, flow *process.Status) {
	r.cpuUtilization.WithLabelValues(commonLabelValues...).
		Set(flow.CPUUtilisationUser + flow.CPUUtilisationSystem + flow.CPUUtilisationWait)
}

// disaggregated observers report three CPU metrics: system, user and wait time
// to be triggered when the user enables the "process_cpu_state" metric
func (r *procMetricsReporter) observeDisaggregatedCPUTime(commonLabelValues []string, flow *process.Status) {
	userLabels := append([]string{"user"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(userLabels...).Add(flow.CPUTimeUserDelta)

	systemLabels := append([]string{"system"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(systemLabels...).Add(flow.CPUTimeSystemDelta)

	waitLabels := append([]string{"wait"}, commonLabelValues...)
	r.cpuTime.WithLabelValues(waitLabels...).Add(flow.CPUTimeWaitDelta)
}

func (r *procMetricsReporter) observeDisaggregatedCPUUtilization(commonLabelValues []string, flow *process.Status) {
	userLabels := append([]string{"user"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(userLabels...).Set(flow.CPUUtilisationUser)

	systemLabels := append([]string{"system"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(systemLabels...).Set(flow.CPUUtilisationSystem)

	waitLabels := append([]string{"wait"}, commonLabelValues...)
	r.cpuUtilization.WithLabelValues(waitLabels...).Set(flow.CPUUtilisationWait)
}

// cpuAttributes returns, for a metric name definition, which attribute names are defined as well as the getters for
// them. It also returns if the invoker must explicitly add the "process.cpu.state" name and value
func cpuAttributes(
	provider *attributes.AttrSelector, metricName attributes.Name,
) (
	names []string, getters []attributes.Field[*process.Status, string], containsState bool,
) {
	attrNames := provider.For(metricName)
	// "process_cpu_state" won't be added by PrometheusGetters, as it's not defined in the *process.Status
	// we need to be aware of the user willing to add it to explicitly choose between
	// observeAggregatedCPU and observeDisaggregatedCPU
	for _, attr := range attrNames {
		containsState = containsState || attr.Prom() == attr2.ProcCPUState.Prom()
	}
	getters = attributes.PrometheusGetters(process.PromGetters, attrNames)

	if containsState {
		// the names and the getters arrays will have different length. The metric value setter
		// observer function, will have to prepend wait/system/user as first value of the attributes list
		names = []string{attr2.ProcCPUState.Prom()}
	}
	for _, label := range getters {
		names = append(names, label.ExposedName)
	}
	return
}
