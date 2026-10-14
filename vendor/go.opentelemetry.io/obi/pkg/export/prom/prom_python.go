// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type pythonRuntimeMetricsCollector struct {
	collections          *Expirer[prometheus.Counter]
	collectedObjects     *Expirer[prometheus.Counter]
	uncollectableObjects *Expirer[prometheus.Counter]
	baseLabelIndexes     []int
	valuesMu             sync.Mutex
	values               map[pythonRuntimeCounterKey]uint64
}

type pythonRuntimeCounterKey struct {
	pid            app.PID
	metric         string
	labelTuple     string
	baseLabelTuple string
}

func newPythonRuntimeMetricsCollector(
	runtimeLabelNames []string,
	clock expire.Clock,
	ttl time.Duration,
) pythonRuntimeMetricsCollector {
	labels := make([]string, 0, len(runtimeLabelNames)+1)
	baseLabelIndexes := make([]int, 0, len(runtimeLabelNames))
	for index, name := range runtimeLabelNames {
		if name == attr.CPythonGCGeneration.Prom() {
			continue
		}
		labels = append(labels, name)
		baseLabelIndexes = append(baseLabelIndexes, index)
	}
	labels = append(labels, attr.CPythonGCGeneration.Prom())
	return pythonRuntimeMetricsCollector{
		collections: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.CPythonGCCollections.Prom,
			Help: "The number of times a generation was collected since interpreter start.",
		}, labels).MetricVec, clock, ttl),
		collectedObjects: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.CPythonGCCollectedObjects.Prom,
			Help: "The total number of objects collected inside a generation since interpreter start.",
		}, labels).MetricVec, clock, ttl),
		uncollectableObjects: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.CPythonGCUncollectableObjects.Prom,
			Help: "The total number of objects which were found to be uncollectable inside a generation since interpreter start.",
		}, labels).MetricVec, clock, ttl),
		baseLabelIndexes: baseLabelIndexes,
		values:           map[pythonRuntimeCounterKey]uint64{},
	}
}

func (c *pythonRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.collections == nil {
		return nil
	}
	return []prometheus.Collector{c.collections, c.collectedObjects, c.uncollectableObjects}
}

func (r *metricsReporter) collectPythonRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if r.pythonRuntimeMetrics.collections == nil || snapshot.Python == nil {
		return
	}

	labels := r.pythonRuntimeMetrics.filterBaseLabels(r.labelValuesTargetInfo(&snapshot.Service))
	if snapshot.Removed {
		r.pythonRuntimeMetrics.deletePID(snapshot.PID)
		return
	}
	for generation, values := range snapshot.Python.Generations {
		generationLabels := append(append([]string{}, labels...), strconv.Itoa(generation))
		r.pythonRuntimeMetrics.addCounter(
			snapshot.PID,
			r.pythonRuntimeMetrics.collections,
			attributes.CPythonGCCollections.Prom,
			generationLabels,
			values.Collections,
		)
		r.pythonRuntimeMetrics.addCounter(
			snapshot.PID,
			r.pythonRuntimeMetrics.collectedObjects,
			attributes.CPythonGCCollectedObjects.Prom,
			generationLabels,
			values.CollectedObjects,
		)
		r.pythonRuntimeMetrics.addCounter(
			snapshot.PID,
			r.pythonRuntimeMetrics.uncollectableObjects,
			attributes.CPythonGCUncollectableObjects.Prom,
			generationLabels,
			values.UncollectableObjects,
		)
	}
}

func (c *pythonRuntimeMetricsCollector) filterBaseLabels(values []string) []string {
	filtered := make([]string, 0, len(c.baseLabelIndexes))
	for _, index := range c.baseLabelIndexes {
		filtered = append(filtered, values[index])
	}
	return filtered
}

func (c *pythonRuntimeMetricsCollector) deletePID(pid app.PID) {
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()

	for key := range c.values {
		if key.pid == pid {
			delete(c.values, key)
		}
	}
}

func (c *pythonRuntimeMetricsCollector) addCounter(
	pid app.PID,
	counter *Expirer[prometheus.Counter],
	metric string,
	labels []string,
	value uint64,
) {
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()

	key := pythonRuntimeCounterKey{
		pid:            pid,
		metric:         metric,
		labelTuple:     runtimeMetricLabelTuple(labels),
		baseLabelTuple: runtimeMetricLabelTuple(labels[:len(c.baseLabelIndexes)]),
	}
	previous, ok := c.values[key]
	entry := counter.WithLabelValues(labels...)
	if !ok || value < previous {
		entry.Metric.Add(float64(value))
	} else if value > previous {
		entry.Metric.Add(float64(value - previous))
	}
	c.values[key] = value
}

func (c *pythonRuntimeMetricsCollector) delete(labels []string) {
	if c.collections == nil {
		return
	}

	baseLabels := c.filterBaseLabels(labels)
	for generation := range runtimemetrics.CPythonGCGenerationCount {
		generationLabels := append(append([]string{}, baseLabels...), strconv.Itoa(generation))
		c.collections.DeleteLabelValues(generationLabels...)
		c.collectedObjects.DeleteLabelValues(generationLabels...)
		c.uncollectableObjects.DeleteLabelValues(generationLabels...)
	}

	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()

	baseLabelTuple := runtimeMetricLabelTuple(baseLabels)
	for key := range c.values {
		if key.baseLabelTuple != baseLabelTuple {
			continue
		}
		delete(c.values, key)
	}
}
