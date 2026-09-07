// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

const jvmNanosPerSecond = float64(time.Second)

type jvmRuntimeMetricsCollector struct {
	memoryUsed            *Expirer[prometheus.Gauge]
	memoryCommitted       *Expirer[prometheus.Gauge]
	memoryLimit           *Expirer[prometheus.Gauge]
	memoryUsedAfterLastGC *Expirer[prometheus.Gauge]
	classLoaded           *prometheus.CounterVec
	classUnloaded         *prometheus.CounterVec
	classCount            *Expirer[prometheus.Gauge]
	threadCount           *Expirer[prometheus.Gauge]
	cpuTime               *prometheus.CounterVec
	cpuCount              *Expirer[prometheus.Gauge]
	cpuRecentUtilization  *Expirer[prometheus.Gauge]
	counters              runtimeCounterTracker
}

func newJVMRuntimeMetricsCollector(cfg *PrometheusConfig) jvmRuntimeMetricsCollector {
	clock := timeNow
	return jvmRuntimeMetricsCollector{
		memoryUsed: newRuntimeGauge(attributes.JVMMemoryUsed.Prom,
			"Current used JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryCommitted: newRuntimeGauge(attributes.JVMMemoryCommitted.Prom,
			"Current committed JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryLimit: newRuntimeGauge(attributes.JVMMemoryLimit.Prom,
			"Current maximum JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryUsedAfterLastGC: newRuntimeGauge(attributes.JVMMemoryUsedAfterLastGC.Prom,
			"JVM memory used after the last garbage collection in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		classLoaded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.JVMClassLoaded.Prom,
			Help: "Total number of classes loaded since the JVM started.",
		}, runtimeServiceLabels()),
		classUnloaded: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.JVMClassUnloaded.Prom,
			Help: "Total number of classes unloaded since the JVM started.",
		}, runtimeServiceLabels()),
		classCount: newRuntimeGauge(attributes.JVMClassCount.Prom,
			"Current number of classes loaded by the JVM.", runtimeServiceLabels(), clock, cfg.TTL),
		threadCount: newRuntimeGauge(attributes.JVMThreadCount.Prom,
			"Current number of JVM platform threads.", jvmThreadLabels(), clock, cfg.TTL),
		cpuTime: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.JVMCPUTime.Prom,
			Help: "CPU time used by the JVM process in seconds.",
		}, runtimeServiceLabels()),
		cpuCount: newRuntimeGauge(attributes.JVMCPUCount.Prom,
			"Number of processors available to the JVM.", runtimeServiceLabels(), clock, cfg.TTL),
		cpuRecentUtilization: newRuntimeGauge(attributes.JVMCPURecentUtilization.Prom,
			"Recent CPU utilization of the JVM process.", runtimeServiceLabels(), clock, cfg.TTL),
	}
}

func (c *jvmRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.memoryUsed == nil {
		return nil
	}
	return []prometheus.Collector{
		c.memoryUsed,
		c.memoryCommitted,
		c.memoryLimit,
		c.memoryUsedAfterLastGC,
		c.classLoaded,
		c.classUnloaded,
		c.classCount,
		c.threadCount,
		c.cpuTime,
		c.cpuCount,
		c.cpuRecentUtilization,
	}
}

func (r *metricsReporter) collectJVMRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.jvmRuntimeMetrics.memoryUsed == nil ||
		snapshot.JVM == nil ||
		!snapshot.Service.ExportModes.CanExportMetrics() ||
		!snapshot.Service.Features.AppRuntime() {
		return
	}
	if values := snapshot.JVM.RuntimeValues; values != nil {
		labels := runtimeServiceLabelValues(snapshot)
		source := jvmRuntimeSource(snapshot.Service.ProcPID, snapshot.Generation)
		r.jvmRuntimeMetrics.counters.addToAggregate(
			r.jvmRuntimeMetrics.classLoaded,
			attributes.JVMClassLoaded.Prom,
			source,
			labels,
			values.TotalLoadedClassCount,
			1,
		)
		r.jvmRuntimeMetrics.counters.addToAggregate(
			r.jvmRuntimeMetrics.classUnloaded,
			attributes.JVMClassUnloaded.Prom,
			source,
			labels,
			values.UnloadedClassCount,
			1,
		)
		r.jvmRuntimeMetrics.classCount.WithLabelValues(labels...).Metric.Set(float64(values.LoadedClassCount))
		daemonThreads := min(values.DaemonThreadCount, values.ThreadCount)
		r.jvmRuntimeMetrics.threadCount.WithLabelValues(
			append(append([]string{}, labels...), "true")...).Metric.Set(float64(daemonThreads))
		r.jvmRuntimeMetrics.threadCount.WithLabelValues(
			append(append([]string{}, labels...), "false")...).Metric.Set(float64(values.ThreadCount - daemonThreads))
		if values.ProcessCPUTimeNS >= 0 {
			r.jvmRuntimeMetrics.counters.addToAggregate(
				r.jvmRuntimeMetrics.cpuTime,
				attributes.JVMCPUTime.Prom,
				source,
				labels,
				uint64(values.ProcessCPUTimeNS),
				1/jvmNanosPerSecond,
			)
		}
		r.jvmRuntimeMetrics.cpuCount.WithLabelValues(labels...).Metric.Set(float64(values.AvailableProcessorCount))
		if values.RecentCPUUtilization >= 0 && values.RecentCPUUtilization <= 1 {
			r.jvmRuntimeMetrics.cpuRecentUtilization.WithLabelValues(labels...).Metric.Set(values.RecentCPUUtilization)
		} else {
			r.jvmRuntimeMetrics.cpuRecentUtilization.DeleteLabelValues(labels...)
		}
		return
	}

	switch snapshot.JVM.Kind {
	case jvmruntime.JVMMetricMemoryUsed:
		r.jvmRuntimeMetrics.memoryUsed.WithLabelValues(jvmMemoryLabelValues(snapshot)...).Metric.Set(float64(snapshot.JVM.ValueBytes))
	case jvmruntime.JVMMetricMemoryCommitted:
		r.jvmRuntimeMetrics.memoryCommitted.WithLabelValues(jvmMemoryLabelValues(snapshot)...).Metric.Set(float64(snapshot.JVM.ValueBytes))
	case jvmruntime.JVMMetricMemoryLimit:
		r.jvmRuntimeMetrics.memoryLimit.WithLabelValues(jvmMemoryLabelValues(snapshot)...).Metric.Set(float64(snapshot.JVM.ValueBytes))
	case jvmruntime.JVMMetricMemoryUsedAfterLastGC:
		r.jvmRuntimeMetrics.memoryUsedAfterLastGC.WithLabelValues(jvmMemoryLabelValues(snapshot)...).Metric.Set(float64(snapshot.JVM.ValueBytes))
	}
}

func (c *jvmRuntimeMetricsCollector) deleteSource(service *svc.Attrs, pid app.PID, generation uint64) {
	if service == nil || c.classLoaded == nil {
		return
	}

	labels := runtimeServiceLabelValuesForService(*service)
	source := jvmRuntimeSource(pid, generation)
	c.counters.deleteAggregateSource(attributes.JVMClassLoaded.Prom, labels, source)
	c.counters.deleteAggregateSource(attributes.JVMClassUnloaded.Prom, labels, source)
	c.counters.deleteAggregateSource(attributes.JVMCPUTime.Prom, labels, source)
}

func jvmRuntimeSource(pid app.PID, generation uint64) string {
	return strconv.Itoa(int(pid)) + ":" + strconv.FormatUint(generation, 10)
}

func jvmMemoryLabels() []string {
	return append(runtimeServiceLabels(), attr.JVMMemoryType.Prom(), attr.JVMMemoryPoolName.Prom())
}

func jvmThreadLabels() []string {
	return append(runtimeServiceLabels(), attr.JVMThreadDaemon.Prom())
}

func jvmMemoryLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return append(runtimeServiceLabelValues(snapshot), string(snapshot.JVM.MemoryType), snapshot.JVM.PoolName)
}
