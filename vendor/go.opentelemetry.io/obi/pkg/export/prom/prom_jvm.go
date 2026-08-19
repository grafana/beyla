// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
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
	}
}

func (r *metricsReporter) collectJVMRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.jvmRuntimeMetrics.memoryUsed == nil ||
		snapshot.JVM == nil ||
		!snapshot.Service.ExportModes.CanExportMetrics() ||
		!snapshot.Service.Features.AppRuntime() {
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

func jvmMemoryLabels() []string {
	return append(runtimeServiceLabels(), attr.JVMMemoryType.Prom(), attr.JVMMemoryPoolName.Prom())
}

func jvmMemoryLabelValues(snapshot runtimemetrics.RuntimeMetricSnapshot) []string {
	return append(runtimeServiceLabelValues(snapshot), string(snapshot.JVM.MemoryType), snapshot.JVM.PoolName)
}
