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
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeMetricsCollector struct {
	memoryLimit       *prometheus.GaugeVec
	memoryGCGoal      *prometheus.GaugeVec
	memoryGCCycles    *prometheus.CounterVec
	memoryUsed        *prometheus.GaugeVec
	memoryAllocated   *prometheus.CounterVec
	memoryAllocations *prometheus.CounterVec
	cpuTime           *prometheus.CounterVec
	goroutineCount    *prometheus.GaugeVec
	processorLimit    *prometheus.GaugeVec
	configGOGC        *prometheus.GaugeVec
	counters          runtimeCounterTracker
}

type runtimeCounterTracker struct {
	mu     sync.Mutex
	values map[string]uint64
}

func newGoRuntimeMetricsCollector(runtimeLabelNames []string) goRuntimeMetricsCollector {
	memoryTypeLabels := append(append([]string{}, runtimeLabelNames...), "go_memory_type")
	cpuTimeLabels := append(append([]string{}, runtimeLabelNames...), "go_cpu_state", "go_cpu_detailed_state")

	return goRuntimeMetricsCollector{
		memoryLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeMemoryLimit.Prom,
			Help: "Runtime memory limit configured by the user, if a limit exists.",
		}, runtimeLabelNames),
		memoryGCGoal: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeMemoryGCGoal.Prom,
			Help: "Heap size target for the next Go garbage collection cycle.",
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
		goroutineCount: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeGoroutineCount.Prom,
			Help: "Number of goroutines that currently exist.",
		}, runtimeLabelNames),
		processorLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeProcessorLimit.Prom,
			Help: "The number of OS threads that can execute user-level Go code simultaneously.",
		}, runtimeLabelNames),
		configGOGC: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeConfigGOGC.Prom,
			Help: "Heap size target percentage configured by the user, otherwise 100.",
		}, runtimeLabelNames),
		counters: runtimeCounterTracker{values: map[string]uint64{}},
	}
}

func (c *goRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.memoryLimit == nil {
		return nil
	}
	return []prometheus.Collector{
		c.memoryLimit,
		c.memoryGCGoal,
		c.memoryGCCycles,
		c.memoryUsed,
		c.memoryAllocated,
		c.memoryAllocations,
		c.cpuTime,
		c.goroutineCount,
		c.processorLimit,
		c.configGOGC,
	}
}

func (r *metricsReporter) collectRuntimeMetrics(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	r.runtimeMu.Lock()
	defer r.runtimeMu.Unlock()
	r.collectRuntimeMetricsLocked(snapshots)
}

func (r *metricsReporter) collectRuntimeMetricsLocked(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	enabled := r.runtimeMetricsEnabled()
	for _, snapshot := range snapshots {
		if !enabled.ShouldReport(snapshot) {
			continue
		}
		if snapshot.Go != nil {
			r.collectGoRuntimeMetrics(snapshot)
		}
		if snapshot.Histogram != nil {
			if r.runtimeSnapshotProcessLive(snapshot) {
				r.collectGoRuntimeHistogram(snapshot)
			}
		}
		if snapshot.JVM != nil {
			if r.runtimeSnapshotProcessLive(snapshot) {
				r.collectJVMRuntimeMetrics(snapshot)
			}
		}
		if snapshot.Nodejs != nil {
			r.collectNodejsRuntimeMetrics(snapshot)
		}
		if snapshot.NodejsGC != nil || snapshot.NodejsHeapSpace != nil || snapshot.NodejsResource != nil {
			r.collectNodejsV8Metrics(snapshot)
		}
		if snapshot.Python != nil {
			if snapshot.Removed || r.runtimeSnapshotProcessLive(snapshot) {
				r.collectPythonRuntimeMetrics(snapshot)
			}
		}
	}
}

func (r *metricsReporter) runtimeSnapshotProcessLive(
	snapshot runtimemetrics.RuntimeMetricSnapshot,
) bool {
	pid := snapshot.PID
	if snapshot.JVM != nil {
		pid = snapshot.Service.ProcPID
	}
	if pid == 0 {
		return true
	}
	return r.pidsTracker.PIDLiveOrUnknown(pid, snapshot.Service.UID, snapshot.Generation)
}

func (r *metricsReporter) runtimeMetricsEnabled() runtimemetrics.Enabled {
	return runtimemetrics.Enabled{
		Runtime: r.goRuntimeMetrics.memoryLimit != nil ||
			r.jvmRuntimeMetrics.memoryUsed != nil ||
			r.nodejsRuntimeMetrics.eventLoopTime != nil ||
			r.pythonRuntimeMetrics.collections != nil,
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
	if snapshot.Go.MemoryGCGoal != nil {
		r.goRuntimeMetrics.memoryGCGoal.WithLabelValues(labels...).Set(float64(*snapshot.Go.MemoryGCGoal))
	} else {
		r.goRuntimeMetrics.memoryGCGoal.DeleteLabelValues(labels...)
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
	if snapshot.Go.GoroutineCount != nil {
		r.goRuntimeMetrics.goroutineCount.WithLabelValues(labels...).Set(float64(*snapshot.Go.GoroutineCount))
	} else {
		r.goRuntimeMetrics.goroutineCount.DeleteLabelValues(labels...)
	}
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

func (r *metricsReporter) collectGoRuntimeHistogram(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.goRuntimeHistograms == nil || snapshot.Histogram == nil {
		return
	}

	r.goRuntimeHistograms.Update(
		snapshot.PID,
		r.labelValuesTargetInfo(&snapshot.Service),
		snapshot.Histogram,
	)
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
	c.counters.add(counter, metric, labels, value, scale)
}

func (c *runtimeCounterTracker) add(
	counter *prometheus.CounterVec,
	metric string,
	labels []string,
	value uint64,
	scale float64,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := runtimeMetricLabelsKey(append([]string{metric}, labels...))
	delta, reset := c.delta(key, value)
	if reset {
		counter.DeleteLabelValues(labels...)
		counter.WithLabelValues(labels...).Add(float64(delta) * scale)
		return
	}
	if delta > 0 {
		counter.WithLabelValues(labels...).Add(float64(delta) * scale)
	}
}

func (c *runtimeCounterTracker) addToAggregate(
	counter *prometheus.CounterVec,
	metric string,
	source string,
	labels []string,
	value uint64,
	scale float64,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyParts := append([]string{metric}, labels...)
	key := runtimeMetricLabelsKey(append(keyParts, source))
	delta, first := c.delta(key, value)
	if delta > 0 || first {
		counter.WithLabelValues(labels...).Add(float64(delta) * scale)
	}
}

func (c *runtimeCounterTracker) delta(key string, value uint64) (uint64, bool) {
	if c.values == nil {
		c.values = map[string]uint64{}
	}
	previous, ok := c.values[key]
	if !ok || value < previous {
		c.values[key] = value
		return value, true
	}

	c.values[key] = value
	return value - previous, false
}

func (c *goRuntimeMetricsCollector) deleteGCCycles(labels []string) {
	c.deleteCounter(c.memoryGCCycles, attributes.GoRuntimeMemoryGCCycles.Prom, labels)
}

func (c *goRuntimeMetricsCollector) deleteCounter(counter *prometheus.CounterVec, metric string, labels []string) {
	c.counters.delete(counter, metric, labels)
}

func (c *runtimeCounterTracker) delete(counter *prometheus.CounterVec, metric string, labels []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.values, runtimeMetricLabelsKey(append([]string{metric}, labels...)))
	counter.DeleteLabelValues(labels...)
}

func (c *runtimeCounterTracker) deleteAggregate(
	counter *prometheus.CounterVec,
	metric string,
	labels []string,
) {
	c.mu.Lock()
	defer c.mu.Unlock()

	prefix := runtimeMetricLabelsKey(append([]string{metric}, labels...))
	for key := range c.values {
		if strings.HasPrefix(key, prefix) {
			delete(c.values, key)
		}
	}
	counter.DeleteLabelValues(labels...)
}

func runtimeMetricLabelsKey(labels []string) string {
	return runtimeMetricLabelTuple(labels)
}

func (c *runtimeCounterTracker) deleteAggregateSource(metric string, labels []string, source string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyParts := append([]string{metric}, labels...)
	delete(c.values, runtimeMetricLabelsKey(append(keyParts, source)))
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

func (r *metricsReporter) deleteRuntimeMetrics(service *svc.Attrs) {
	if service == nil {
		return
	}

	labels := r.labelValuesTargetInfo(service)
	if r.goRuntimeMetrics.memoryLimit != nil {
		r.goRuntimeMetrics.memoryLimit.DeleteLabelValues(labels...)
		r.goRuntimeMetrics.memoryGCGoal.DeleteLabelValues(labels...)
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
		r.goRuntimeMetrics.goroutineCount.DeleteLabelValues(labels...)
		r.goRuntimeMetrics.processorLimit.DeleteLabelValues(labels...)
		r.goRuntimeMetrics.configGOGC.DeleteLabelValues(labels...)
	}

	// Keep the shared JVM counters while any PID still belongs to this
	// service. Delete them only when the service loses its final PID.
	if r.jvmRuntimeMetrics.classLoaded == nil ||
		r.pidsTracker.ServiceLive(service.UID) {
		return
	}
	jvmLabels := runtimeServiceLabelValuesForService(*service)
	r.jvmRuntimeMetrics.counters.deleteAggregate(
		r.jvmRuntimeMetrics.classLoaded,
		attributes.JVMClassLoaded.Prom,
		jvmLabels,
	)
	r.jvmRuntimeMetrics.counters.deleteAggregate(
		r.jvmRuntimeMetrics.classUnloaded,
		attributes.JVMClassUnloaded.Prom,
		jvmLabels,
	)
	r.jvmRuntimeMetrics.counters.deleteAggregate(
		r.jvmRuntimeMetrics.cpuTime,
		attributes.JVMCPUTime.Prom,
		jvmLabels,
	)
}

func (r *metricsReporter) deleteRuntimeHistograms(service *svc.Attrs) {
	if service != nil && r.goRuntimeHistograms != nil {
		r.goRuntimeHistograms.Delete(r.labelValuesTargetInfo(service))
	}
}

// Labels shared by the JVM and Node.js runtime metric collectors.

func runtimeServiceLabels() []string {
	return []string{
		attr.ServiceName.Prom(),
		attr.ServiceNamespace.Prom(),
		attr.ServiceInstanceID.Prom(),
	}
}

func runtimeServiceLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return runtimeServiceLabelValuesForService(snapshot.Service)
}

func runtimeServiceLabelValuesForService(service svc.Attrs) []string {
	return []string{
		service.UID.Name,
		service.UID.Namespace,
		service.UID.Instance,
	}
}

func newRuntimeGauge(name, help string, labels []string, clock func() time.Time, ttl time.Duration) *Expirer[prometheus.Gauge] {
	return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels).MetricVec, clock, ttl)
}
