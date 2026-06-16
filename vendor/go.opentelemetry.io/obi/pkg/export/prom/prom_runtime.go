// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type goRuntimeMetricsCollector struct {
	memoryLimit    *prometheus.GaugeVec
	memoryGCCycles *prometheus.CounterVec
	processorLimit *prometheus.GaugeVec
	configGOGC     *prometheus.GaugeVec
	gcCyclesMu     sync.Mutex
	gcCycles       map[string]uint64
}

func newGoRuntimeMetricsCollector(runtimeLabelNames []string) goRuntimeMetricsCollector {
	return goRuntimeMetricsCollector{
		memoryLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeMemoryLimit.Prom,
			Help: "Runtime memory limit configured by the user, if a limit exists.",
		}, runtimeLabelNames),
		memoryGCCycles: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.GoRuntimeMemoryGCCycles.Prom,
			Help: "Number of completed Go garbage collection cycles.",
		}, runtimeLabelNames),
		processorLimit: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeProcessorLimit.Prom,
			Help: "The number of OS threads that can execute user-level Go code simultaneously.",
		}, runtimeLabelNames),
		configGOGC: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attributes.GoRuntimeConfigGOGC.Prom,
			Help: "Heap size target percentage configured by the user, otherwise 100.",
		}, runtimeLabelNames),
		gcCycles: map[string]uint64{},
	}
}

func (c *goRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.memoryLimit == nil {
		return nil
	}
	return []prometheus.Collector{
		c.memoryLimit,
		c.memoryGCCycles,
		c.processorLimit,
		c.configGOGC,
	}
}

func (r *metricsReporter) collectRuntimeMetrics(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	for _, snapshot := range snapshots {
		if snapshot.Service.SDKLanguage != svc.InstrumentableGolang {
			continue
		}
		r.collectGoRuntimeMetrics(snapshot)
	}
}

func (r *metricsReporter) watchForRuntimeMetrics(ctx context.Context) {
	log := mlog().With("function", "watchForRuntimeMetrics")
	swarms.ForEachInput(ctx, r.runtimeInput, log.Debug, r.collectRuntimeMetrics)
}

func (r *metricsReporter) collectGoRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.goRuntimeMetrics.memoryLimit == nil {
		return
	}

	labels := r.labelValuesTargetInfo(&snapshot.Service)
	if snapshot.MemoryLimit != nil {
		r.goRuntimeMetrics.memoryLimit.WithLabelValues(labels...).Set(float64(*snapshot.MemoryLimit))
	} else {
		r.goRuntimeMetrics.memoryLimit.DeleteLabelValues(labels...)
	}
	if snapshot.GCCycles != nil {
		r.goRuntimeMetrics.addGCCycles(labels, *snapshot.GCCycles)
	} else {
		r.goRuntimeMetrics.deleteGCCycles(labels)
	}
	if snapshot.ProcessorLimit != nil {
		r.goRuntimeMetrics.processorLimit.WithLabelValues(labels...).Set(float64(*snapshot.ProcessorLimit))
	} else {
		r.goRuntimeMetrics.processorLimit.DeleteLabelValues(labels...)
	}
	if snapshot.GOGC != nil {
		r.goRuntimeMetrics.configGOGC.WithLabelValues(labels...).Set(float64(*snapshot.GOGC))
	} else {
		r.goRuntimeMetrics.configGOGC.DeleteLabelValues(labels...)
	}
}

func (c *goRuntimeMetricsCollector) addGCCycles(labels []string, value uint64) {
	c.gcCyclesMu.Lock()
	defer c.gcCyclesMu.Unlock()

	key := runtimeMetricLabelsKey(labels)
	if c.gcCycles == nil {
		c.gcCycles = map[string]uint64{}
	}
	previous, ok := c.gcCycles[key]
	if !ok || value < previous {
		c.memoryGCCycles.DeleteLabelValues(labels...)
		c.memoryGCCycles.WithLabelValues(labels...).Add(float64(value))
		c.gcCycles[key] = value
		return
	}

	if value > previous {
		c.memoryGCCycles.WithLabelValues(labels...).Add(float64(value - previous))
	}
	c.gcCycles[key] = value
}

func (c *goRuntimeMetricsCollector) deleteGCCycles(labels []string) {
	c.gcCyclesMu.Lock()
	defer c.gcCyclesMu.Unlock()

	delete(c.gcCycles, runtimeMetricLabelsKey(labels))
	c.memoryGCCycles.DeleteLabelValues(labels...)
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
	r.goRuntimeMetrics.processorLimit.DeleteLabelValues(labels...)
	r.goRuntimeMetrics.configGOGC.DeleteLabelValues(labels...)
}
