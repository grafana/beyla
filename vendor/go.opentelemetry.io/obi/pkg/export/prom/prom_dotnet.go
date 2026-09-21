// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type dotnetRuntimeMetricsCollector struct {
	collections      *Expirer[prometheus.Counter]
	baseLabelIndexes []int
	valuesMu         sync.Mutex
	values           map[dotnetRuntimeCounterKey]uint64
}

type dotnetRuntimeCounterKey struct {
	pid        app.PID
	generation uint64
	labels     string
	baseLabels string
}

func (c *dotnetRuntimeMetricsCollector) delete(values []string) {
	if c.collections == nil {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	labels := make([]string, 0, len(c.baseLabelIndexes)+1)
	for _, index := range c.baseLabelIndexes {
		labels = append(labels, values[index])
	}
	baseLabels := runtimeMetricLabelTuple(labels)
	labels = append(labels, "")
	for generation := range runtimemetrics.DotnetGCGenerationCount {
		labels[len(labels)-1] = fmt.Sprintf("gen%d", generation)
		c.collections.DeleteLabelValues(labels...)
	}
	for key := range c.values {
		if key.baseLabels == baseLabels {
			delete(c.values, key)
		}
	}
}

func (r *metricsReporter) collectDotnetRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	c := &r.dotnetRuntimeMetrics
	if c.collections == nil || snapshot.Dotnet == nil {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	if snapshot.Removed {
		for key := range c.values {
			if key.pid == snapshot.PID && key.generation == snapshot.Generation {
				delete(c.values, key)
			}
		}
		return
	}
	if c.values == nil {
		c.values = make(map[dotnetRuntimeCounterKey]uint64)
	}
	for key := range c.values {
		if key.pid == snapshot.PID && key.generation != snapshot.Generation {
			delete(c.values, key)
		}
	}
	base := r.labelValuesTargetInfo(&snapshot.Service)
	labels := make([]string, 0, len(c.baseLabelIndexes)+1)
	for _, index := range c.baseLabelIndexes {
		labels = append(labels, base[index])
	}
	labels = append(labels, "")
	for generation, value := range snapshot.Dotnet.GCCollections {
		if value == nil {
			continue
		}
		labels[len(labels)-1] = fmt.Sprintf("gen%d", generation)
		key := dotnetRuntimeCounterKey{
			pid: snapshot.PID, generation: snapshot.Generation, labels: runtimeMetricLabelTuple(labels),
			baseLabels: runtimeMetricLabelTuple(labels[:len(labels)-1]),
		}
		previous, exists := c.values[key]
		entry := c.collections.WithLabelValues(labels...)
		if !exists || *value < previous {
			entry.Metric.Add(float64(*value))
		} else if *value > previous {
			entry.Metric.Add(float64(*value - previous))
		}
		c.values[key] = *value
	}
}

func newDotnetRuntimeMetricsCollector(runtimeLabelNames []string, clock expire.Clock, ttl time.Duration) dotnetRuntimeMetricsCollector {
	labels := make([]string, 0, len(runtimeLabelNames)+1)
	baseLabelIndexes := make([]int, 0, len(runtimeLabelNames))
	for index, name := range runtimeLabelNames {
		if name == attr.DotnetGCHeapGeneration.Prom() {
			continue
		}
		labels = append(labels, name)
		baseLabelIndexes = append(baseLabelIndexes, index)
	}
	labels = append(labels, attr.DotnetGCHeapGeneration.Prom())
	return dotnetRuntimeMetricsCollector{
		collections: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetGCCollections.Prom,
			Help: "The number of garbage collections since the collector baseline, exclusive per generation.",
		}, labels).MetricVec, clock, ttl),
		baseLabelIndexes: baseLabelIndexes,
	}
}
