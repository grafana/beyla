// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type jvmRuntimeMetricsCollector struct {
	memoryUsed            *Expirer[prometheus.Gauge]
	memoryCommitted       *Expirer[prometheus.Gauge]
	memoryLimit           *Expirer[prometheus.Gauge]
	memoryUsedAfterLastGC *Expirer[prometheus.Gauge]
	heapUsed              *Expirer[prometheus.Gauge]
}

func newJVMRuntimeMetricsCollector(cfg *PrometheusConfig) jvmRuntimeMetricsCollector {
	clock := timeNow
	return jvmRuntimeMetricsCollector{
		memoryUsed: newJVMGauge(attributes.JVMMemoryUsed.Prom,
			"Current used JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryCommitted: newJVMGauge(attributes.JVMMemoryCommitted.Prom,
			"Current committed JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryLimit: newJVMGauge(attributes.JVMMemoryLimit.Prom,
			"Current maximum JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryUsedAfterLastGC: newJVMGauge(attributes.JVMMemoryUsedAfterLastGC.Prom,
			"JVM memory used after the last garbage collection in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		heapUsed: newJVMGauge(attributes.ObiJVMHeapUsed.Prom,
			"HotSpot heap used in bytes as reported by GCTracer::report_gc_heap_summary.", jvmHeapLabels(), clock, cfg.TTL),
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
		c.heapUsed,
	}
}

func newJVMGauge(name, help string, labels []string, clock func() time.Time, ttl time.Duration) *Expirer[prometheus.Gauge] {
	return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels).MetricVec, clock, ttl)
}

func (r *metricsReporter) collectJVMRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.jvmRuntimeMetrics.memoryUsed == nil ||
		snapshot.JVM == nil ||
		!snapshot.Service.ExportModes.CanExportMetrics() ||
		!snapshot.Service.Features.AppJVM() {
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
	case jvmruntime.JVMMetricObiHeapUsed:
		r.jvmRuntimeMetrics.heapUsed.WithLabelValues(jvmHeapLabelValues(snapshot)...).Metric.Set(float64(snapshot.JVM.ValueBytes))
	}
}

func jvmServiceLabels() []string {
	return []string{
		attr.ServiceName.Prom(),
		attr.ServiceNamespace.Prom(),
		attr.ServiceInstanceID.Prom(),
	}
}

func jvmMemoryLabels() []string {
	return append(jvmServiceLabels(), attr.JVMMemoryType.Prom(), attr.JVMMemoryPoolName.Prom())
}

func jvmHeapLabels() []string {
	return append(jvmServiceLabels(), attr.JVMGCPhase.Prom())
}

func jvmServiceLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return []string{
		snapshot.Service.UID.Name,
		snapshot.Service.UID.Namespace,
		snapshot.Service.UID.Instance,
	}
}

func jvmMemoryLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return append(jvmServiceLabelValues(snapshot), string(snapshot.JVM.MemoryType), snapshot.JVM.PoolName)
}

func jvmHeapLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return append(jvmServiceLabelValues(snapshot), string(snapshot.JVM.GCPhase))
}
