// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeMetricsCollector struct {
	memoryLimit       *prometheus.GaugeVec
	memoryGCCycles    *prometheus.CounterVec
	memoryUsed        *prometheus.GaugeVec
	memoryAllocated   *prometheus.CounterVec
	memoryAllocations *prometheus.CounterVec
	cpuTime           *prometheus.CounterVec
	processorLimit    *prometheus.GaugeVec
	configGOGC        *prometheus.GaugeVec
	counterValuesMu   sync.Mutex
	counterValues     map[string]uint64
}

func newGoRuntimeMetricsCollector(runtimeLabelNames []string) goRuntimeMetricsCollector {
	memoryTypeLabels := append(append([]string{}, runtimeLabelNames...), "go_memory_type")
	cpuTimeLabels := append(append([]string{}, runtimeLabelNames...), "go_cpu_state", "go_cpu_detailed_state")

	return goRuntimeMetricsCollector{
		memoryLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeMemoryLimit.Prom,
			Help: "Runtime memory limit configured by the user, if a limit exists.",
		}, runtimeLabelNames),
		memoryGCCycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.GoRuntimeMemoryGCCycles.Prom,
			Help: "Number of completed Go garbage collection cycles.",
		}, runtimeLabelNames),
		memoryUsed: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeMemoryUsed.Prom,
			Help: "Memory used by the Go runtime.",
		}, memoryTypeLabels),
		memoryAllocated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.GoRuntimeMemoryAllocated.Prom,
			Help: "Memory allocated by the Go runtime heap.",
		}, runtimeLabelNames),
		memoryAllocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.GoRuntimeMemoryAllocations.Prom,
			Help: "Number of Go runtime heap allocations.",
		}, runtimeLabelNames),
		cpuTime: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.GoRuntimeCPUTime.Prom,
			Help: "Estimated CPU time spent by the Go runtime.",
		}, cpuTimeLabels),
		processorLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeProcessorLimit.Prom,
			Help: "The number of OS threads that can execute user-level Go code simultaneously.",
		}, runtimeLabelNames),
		configGOGC: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeConfigGOGC.Prom,
			Help: "Heap size target percentage configured by the user, otherwise 100.",
		}, runtimeLabelNames),
		counterValues: map[string]uint64{},
	}
}

func (c *goRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.memoryLimit == nil {
		return nil
	}
	return []prometheus.Collector{
		c.memoryLimit,
		c.memoryGCCycles,
		c.memoryUsed,
		c.memoryAllocated,
		c.memoryAllocations,
		c.cpuTime,
		c.processorLimit,
		c.configGOGC,
	}
}

func (r *metricsReporter) collectRuntimeMetrics(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	enabled := r.runtimeMetricsEnabled()
	for _, snapshot := range snapshots {
		if !enabled.ShouldReport(snapshot) {
			continue
		}
		if snapshot.Go != nil {
			r.collectGoRuntimeMetrics(snapshot)
		}
		if snapshot.JVM != nil {
			r.collectJVMRuntimeMetrics(snapshot)
		}
	}
}

func (r *metricsReporter) runtimeMetricsEnabled() runtimemetrics.Enabled {
	return runtimemetrics.Enabled{
		Runtime: r.goRuntimeMetrics.memoryLimit != nil && r.jvmRuntimeMetrics.memoryUsed != nil,
	}
}

func (r *metricsReporter) watchForRuntimeMetrics(ctx context.Context) {
	log := mlog().With("function", "watchForRuntimeMetrics")
	swarms.ForEachInput(ctx, r.runtimeInput, log.Debug, r.collectRuntimeMetrics)
}

func (r *metricsReporter) collectGoRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.goRuntimeMetrics.memoryLimit == nil || snapshot.Go == nil {
		return
	}

	labels := r.labelValuesTargetInfo(&snapshot.Service)
	if snapshot.Go.MemoryLimit != nil {
		r.goRuntimeMetrics.memoryLimit.WithLabelValues(labels...).Set(float64(*snapshot.Go.MemoryLimit))
	} else {
		r.goRuntimeMetrics.memoryLimit.DeleteLabelValues(labels...)
	}
	if snapshot.Go.GCCycles != nil {
		r.goRuntimeMetrics.addGCCycles(labels, *snapshot.Go.GCCycles)
	} else {
		r.goRuntimeMetrics.deleteGCCycles(labels)
	}
	stackLabels := append(append([]string{}, labels...), "stack")
	if snapshot.Go.MemoryUsedStack != nil {
		r.goRuntimeMetrics.memoryUsed.WithLabelValues(stackLabels...).Set(float64(*snapshot.Go.MemoryUsedStack))
	} else {
		r.goRuntimeMetrics.memoryUsed.DeleteLabelValues(stackLabels...)
	}
	otherLabels := append(append([]string{}, labels...), "other")
	if snapshot.Go.MemoryUsedOther != nil {
		r.goRuntimeMetrics.memoryUsed.WithLabelValues(otherLabels...).Set(float64(*snapshot.Go.MemoryUsedOther))
	} else {
		r.goRuntimeMetrics.memoryUsed.DeleteLabelValues(otherLabels...)
	}
	if snapshot.Go.MemoryAllocated != nil {
		r.goRuntimeMetrics.addCounter(
			r.goRuntimeMetrics.memoryAllocated,
			attributes.GoRuntimeMemoryAllocated.Prom,
			labels,
			*snapshot.Go.MemoryAllocated,
			1,
		)
	} else {
		r.goRuntimeMetrics.deleteCounter(
			r.goRuntimeMetrics.memoryAllocated,
			attributes.GoRuntimeMemoryAllocated.Prom,
			labels,
		)
	}
	if snapshot.Go.MemoryAllocations != nil {
		r.goRuntimeMetrics.addCounter(
			r.goRuntimeMetrics.memoryAllocations,
			attributes.GoRuntimeMemoryAllocations.Prom,
			labels,
			*snapshot.Go.MemoryAllocations,
			1,
		)
	} else {
		r.goRuntimeMetrics.deleteCounter(
			r.goRuntimeMetrics.memoryAllocations,
			attributes.GoRuntimeMemoryAllocations.Prom,
			labels,
		)
	}
	r.goRuntimeMetrics.collectCPUTime(labels, snapshot.Go.CPUTime)
	if snapshot.Go.ProcessorLimit != nil {
		r.goRuntimeMetrics.processorLimit.WithLabelValues(labels...).Set(float64(*snapshot.Go.ProcessorLimit))
	} else {
		r.goRuntimeMetrics.processorLimit.DeleteLabelValues(labels...)
	}
	if snapshot.Go.GOGC != nil {
		r.goRuntimeMetrics.configGOGC.WithLabelValues(labels...).Set(float64(*snapshot.Go.GOGC))
	} else {
		r.goRuntimeMetrics.configGOGC.DeleteLabelValues(labels...)
	}
}

func (c *goRuntimeMetricsCollector) addGCCycles(labels []string, value uint64) {
	c.addCounter(c.memoryGCCycles, attributes.GoRuntimeMemoryGCCycles.Prom, labels, value, 1)
}

func (c *goRuntimeMetricsCollector) addCounter(
	counter *prometheus.CounterVec,
	metric string,
	labels []string,
	value uint64,
	scale float64,
) {
	c.counterValuesMu.Lock()
	defer c.counterValuesMu.Unlock()

	key := runtimeMetricLabelsKey(append([]string{metric}, labels...))
	if c.counterValues == nil {
		c.counterValues = map[string]uint64{}
	}
	previous, ok := c.counterValues[key]
	if !ok || value < previous {
		counter.DeleteLabelValues(labels...)
		counter.WithLabelValues(labels...).Add(float64(value) * scale)
		c.counterValues[key] = value
		return
	}

	if value > previous {
		counter.WithLabelValues(labels...).Add(float64(value-previous) * scale)
	}
	c.counterValues[key] = value
}

func (c *goRuntimeMetricsCollector) deleteGCCycles(labels []string) {
	c.deleteCounter(c.memoryGCCycles, attributes.GoRuntimeMemoryGCCycles.Prom, labels)
}

func (c *goRuntimeMetricsCollector) deleteCounter(counter *prometheus.CounterVec, metric string, labels []string) {
	c.counterValuesMu.Lock()
	defer c.counterValuesMu.Unlock()

	delete(c.counterValues, runtimeMetricLabelsKey(append([]string{metric}, labels...)))
	counter.DeleteLabelValues(labels...)
}

func (c *goRuntimeMetricsCollector) collectCPUTime(
	labels []string,
	cpu *runtimemetrics.GoRuntimeCPUTimeSnapshot,
) {
	if cpu == nil {
		c.deleteCPUTime(labels)
		return
	}

	for _, value := range runtimemetrics.GoRuntimeCPUTimeValues(cpu) {
		c.collectCPUTimeValue(labels, value.State, value.DetailedState, value.Nanoseconds)
	}
}

func (c *goRuntimeMetricsCollector) collectCPUTimeValue(
	labels []string,
	state string,
	detailedState string,
	value int64,
) {
	cpuLabels := append(append([]string{}, labels...), state, detailedState)
	c.addCounter(c.cpuTime, attributes.GoRuntimeCPUTime.Prom, cpuLabels, uint64(value), 1/float64(time.Second))
}

func (c *goRuntimeMetricsCollector) deleteCPUTime(labels []string) {
	for _, value := range runtimemetrics.GoRuntimeCPUTimeValues(nil) {
		c.deleteCPUTimeValue(labels, value.State, value.DetailedState)
	}
}

func (c *goRuntimeMetricsCollector) deleteCPUTimeValue(labels []string, state string, detailedState string) {
	cpuLabels := append(append([]string{}, labels...), state, detailedState)
	c.deleteCounter(c.cpuTime, attributes.GoRuntimeCPUTime.Prom, cpuLabels)
}

func runtimeMetricLabelsKey(labels []string) string {
	return strings.Join(labels, "\xff")
}

func (r *metricsReporter) deleteRuntimeMetrics(service *svc.Attrs) {
	if service == nil || r.goRuntimeMetrics.memoryLimit == nil {
		return
	}

	labels := r.labelValuesTargetInfo(service)
	r.goRuntimeMetrics.memoryLimit.DeleteLabelValues(labels...)
	r.goRuntimeMetrics.deleteGCCycles(labels)
	r.goRuntimeMetrics.memoryUsed.DeleteLabelValues(append(append([]string{}, labels...), "stack")...)
	r.goRuntimeMetrics.memoryUsed.DeleteLabelValues(append(append([]string{}, labels...), "other")...)
	r.goRuntimeMetrics.deleteCounter(
		r.goRuntimeMetrics.memoryAllocated,
		attributes.GoRuntimeMemoryAllocated.Prom,
		labels,
	)
	r.goRuntimeMetrics.deleteCounter(
		r.goRuntimeMetrics.memoryAllocations,
		attributes.GoRuntimeMemoryAllocations.Prom,
		labels,
	)
	r.goRuntimeMetrics.deleteCPUTime(labels)
	r.goRuntimeMetrics.processorLimit.DeleteLabelValues(labels...)
	r.goRuntimeMetrics.configGOGC.DeleteLabelValues(labels...)
}
