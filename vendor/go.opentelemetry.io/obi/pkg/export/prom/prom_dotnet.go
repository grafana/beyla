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
	collections             *Expirer[prometheus.Counter]
	gcHeapTotalAllocated    *Expirer[prometheus.Counter]
	gcPauseTime             *Expirer[prometheus.Counter]
	jitCompiledILSize       *Expirer[prometheus.Counter]
	jitCompiledMethods      *Expirer[prometheus.Counter]
	jitCompilationTime      *Expirer[prometheus.Counter]
	threadPoolWorkItemCount *Expirer[prometheus.Counter]
	monitorLockContentions  *Expirer[prometheus.Counter]
	processMemoryWorkingSet *Expirer[prometheus.Gauge]
	gcCommittedMemory       *Expirer[prometheus.Gauge]
	threadPoolThreadCount   *Expirer[prometheus.Gauge]
	threadPoolQueueLength   *Expirer[prometheus.Gauge]
	timerCount              *Expirer[prometheus.Gauge]
	assemblyCount           *Expirer[prometheus.Gauge]
	baseLabelIndexes        []int
	valuesMu                sync.Mutex
	values                  map[dotnetRuntimeCounterKey]uint64
	durationValues          map[dotnetRuntimeCounterKey]float64
	currentValues           map[app.PID]dotnetRuntimeCurrentValues
	currentAggregates       map[string]*dotnetRuntimeCurrentAggregate
	clock                   expire.Clock
	lastExpiration          time.Time
	ttl                     time.Duration
}

type dotnetRuntimeCurrentValues struct {
	generation uint64
	lastSeen   time.Time
	labels     []string
	labelTuple string
	values     runtimemetrics.DotnetRuntimeMetricSnapshot
}

type dotnetRuntimeGaugeAggregate struct {
	sum          float64
	contributors int
}

type dotnetRuntimeCurrentAggregate struct {
	processMemoryWorkingSet dotnetRuntimeGaugeAggregate
	gcCommittedMemory       dotnetRuntimeGaugeAggregate
	threadPoolThreadCount   dotnetRuntimeGaugeAggregate
	threadPoolQueueLength   dotnetRuntimeGaugeAggregate
	timerCount              dotnetRuntimeGaugeAggregate
	assemblyCount           dotnetRuntimeGaugeAggregate
}

type dotnetRuntimeCounterKey struct {
	pid        app.PID
	generation uint64
	metric     string
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
	for _, counter := range []*Expirer[prometheus.Counter]{
		c.gcHeapTotalAllocated,
		c.gcPauseTime,
		c.jitCompiledILSize,
		c.jitCompiledMethods,
		c.jitCompilationTime,
		c.threadPoolWorkItemCount,
		c.monitorLockContentions,
	} {
		counter.DeleteLabelValues(labels...)
	}
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
	for key := range c.durationValues {
		if key.baseLabels == baseLabels {
			delete(c.durationValues, key)
		}
	}
	for pid, current := range c.currentValues {
		if current.labelTuple == baseLabels {
			c.updateCurrentMetrics(current, nil)
			delete(c.currentValues, pid)
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
		if previous, exists := c.currentValues[snapshot.PID]; exists && previous.generation == snapshot.Generation {
			c.updateCurrentMetrics(previous, nil)
			delete(c.currentValues, snapshot.PID)
		}
		for key := range c.values {
			if key.pid == snapshot.PID && key.generation == snapshot.Generation {
				delete(c.values, key)
			}
		}
		for key := range c.durationValues {
			if key.pid == snapshot.PID && key.generation == snapshot.Generation {
				delete(c.durationValues, key)
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
	for key := range c.durationValues {
		if key.pid == snapshot.PID && key.generation != snapshot.Generation {
			delete(c.durationValues, key)
		}
	}
	base := r.labelValuesTargetInfo(&snapshot.Service)
	labels := make([]string, 0, len(c.baseLabelIndexes)+1)
	for _, index := range c.baseLabelIndexes {
		labels = append(labels, base[index])
	}
	if c.currentValues == nil {
		c.currentValues = make(map[app.PID]dotnetRuntimeCurrentValues)
	}
	previous, existed := c.currentValues[snapshot.PID]
	current := dotnetRuntimeCurrentValues{
		generation: snapshot.Generation,
		lastSeen:   c.clock(),
		labels:     append([]string(nil), labels...),
		labelTuple: runtimeMetricLabelTuple(labels),
		values:     *snapshot.Dotnet,
	}
	var oldValues runtimemetrics.DotnetRuntimeMetricSnapshot
	if existed {
		if previous.labelTuple == current.labelTuple {
			oldValues = previous.values
		} else {
			c.updateCurrentMetrics(previous, nil)
		}
	}
	c.currentValues[snapshot.PID] = current
	replacement := current
	replacement.values = oldValues
	c.updateCurrentMetrics(replacement, &current.values)
	for _, counter := range []struct {
		name   string
		metric *Expirer[prometheus.Counter]
		value  *uint64
	}{
		{attributes.DotnetGCHeapTotalAllocated.Prom, c.gcHeapTotalAllocated, snapshot.Dotnet.GCHeapTotalAllocated},
		{attributes.DotnetJITCompiledILSize.Prom, c.jitCompiledILSize, snapshot.Dotnet.JITCompiledILSize},
		{attributes.DotnetJITCompiledMethods.Prom, c.jitCompiledMethods, snapshot.Dotnet.JITCompiledMethods},
		{attributes.DotnetThreadPoolWorkItemCount.Prom, c.threadPoolWorkItemCount, snapshot.Dotnet.ThreadPoolWorkItemCount},
		{attributes.DotnetMonitorLockContentions.Prom, c.monitorLockContentions, snapshot.Dotnet.MonitorLockContentions},
	} {
		if counter.value == nil {
			continue
		}
		key := dotnetRuntimeCounterKey{
			pid: snapshot.PID, generation: snapshot.Generation, metric: counter.name,
			labels: current.labelTuple, baseLabels: current.labelTuple,
		}
		var baseline *uint64
		if previous, exists := c.values[key]; exists {
			baseline = &previous
		}
		delta := runtimemetrics.CounterDelta(baseline, *counter.value)
		counter.metric.WithLabelValues(labels...).Metric.Add(float64(delta))
		c.values[key] = *counter.value
	}
	if c.durationValues == nil {
		c.durationValues = make(map[dotnetRuntimeCounterKey]float64)
	}
	for _, counter := range []struct {
		name   string
		metric *Expirer[prometheus.Counter]
		value  *float64
	}{
		{attributes.DotnetGCPauseTime.Prom, c.gcPauseTime, snapshot.Dotnet.GCPauseTime},
		{attributes.DotnetJITCompilationTime.Prom, c.jitCompilationTime, snapshot.Dotnet.JITCompilationTime},
	} {
		if counter.value == nil {
			continue
		}
		key := dotnetRuntimeCounterKey{
			pid: snapshot.PID, generation: snapshot.Generation, metric: counter.name,
			labels: current.labelTuple, baseLabels: current.labelTuple,
		}
		var baseline *float64
		if previous, exists := c.durationValues[key]; exists {
			baseline = &previous
		}
		delta := runtimemetrics.CounterDelta(baseline, *counter.value)
		counter.metric.WithLabelValues(labels...).Metric.Add(delta)
		c.durationValues[key] = *counter.value
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

func (c *dotnetRuntimeMetricsCollector) expireCurrentMetrics() {
	if c.ttl == 0 {
		return
	}
	c.valuesMu.Lock()
	defer c.valuesMu.Unlock()
	now := c.clock()
	if !c.lastExpiration.IsZero() && now.Sub(c.lastExpiration) <= c.ttl {
		return
	}
	c.lastExpiration = now
	for pid, current := range c.currentValues {
		if now.Sub(current.lastSeen) > c.ttl {
			c.updateCurrentMetrics(current, nil)
			delete(c.currentValues, pid)
		}
	}
}

// updateCurrentMetrics runs with valuesMu held. Contributor counts keep reported
// zero values distinct from metrics with no available process samples.
func (c *dotnetRuntimeMetricsCollector) updateCurrentMetrics(entry dotnetRuntimeCurrentValues, next *runtimemetrics.DotnetRuntimeMetricSnapshot) {
	if next == nil {
		next = &runtimemetrics.DotnetRuntimeMetricSnapshot{}
	}
	if c.currentAggregates == nil {
		c.currentAggregates = make(map[string]*dotnetRuntimeCurrentAggregate)
	}
	aggregate := c.currentAggregates[entry.labelTuple]
	if aggregate == nil {
		aggregate = &dotnetRuntimeCurrentAggregate{}
		c.currentAggregates[entry.labelTuple] = aggregate
	}
	available := false
	for _, current := range []struct {
		metric    *Expirer[prometheus.Gauge]
		aggregate *dotnetRuntimeGaugeAggregate
		value     *int64
		next      *int64
	}{
		{c.processMemoryWorkingSet, &aggregate.processMemoryWorkingSet, entry.values.ProcessMemoryWorkingSet, next.ProcessMemoryWorkingSet},
		{c.gcCommittedMemory, &aggregate.gcCommittedMemory, entry.values.GCCommittedMemory, next.GCCommittedMemory},
		{c.threadPoolThreadCount, &aggregate.threadPoolThreadCount, entry.values.ThreadPoolThreadCount, next.ThreadPoolThreadCount},
		{c.threadPoolQueueLength, &aggregate.threadPoolQueueLength, entry.values.ThreadPoolQueueLength, next.ThreadPoolQueueLength},
		{c.timerCount, &aggregate.timerCount, entry.values.TimerCount, next.TimerCount},
		{c.assemblyCount, &aggregate.assemblyCount, entry.values.AssemblyCount, next.AssemblyCount},
	} {
		if current.value != nil {
			current.aggregate.sum -= float64(*current.value)
			current.aggregate.contributors--
		}
		if current.aggregate.contributors == 0 {
			current.aggregate.sum = 0
		}
		if current.next != nil {
			current.aggregate.sum += float64(*current.next)
			current.aggregate.contributors++
		}
		if current.aggregate.contributors > 0 {
			available = true
			current.metric.WithLabelValues(entry.labels...).Metric.Set(current.aggregate.sum)
		} else {
			current.aggregate.sum = 0
			current.metric.DeleteLabelValues(entry.labels...)
		}
	}
	if !available {
		delete(c.currentAggregates, entry.labelTuple)
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
	baseLabels := labels
	labels = append(labels, attr.DotnetGCHeapGeneration.Prom())
	return dotnetRuntimeMetricsCollector{
		collections: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetGCCollections.Prom,
			Help: "The number of garbage collections since the collector baseline, exclusive per generation.",
		}, labels).MetricVec, clock, ttl),
		gcHeapTotalAllocated: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetGCHeapTotalAllocated.Prom,
			Help: "Total bytes allocated on the .NET managed heap since the collector baseline.",
		}, baseLabels).MetricVec, clock, ttl),
		gcPauseTime: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetGCPauseTime.Prom,
			Help: "Total .NET GC pause time in seconds since the collector baseline.",
		}, baseLabels).MetricVec, clock, ttl),
		jitCompiledILSize: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetJITCompiledILSize.Prom,
			Help: "Total bytes of intermediate language compiled by the .NET JIT compiler.",
		}, baseLabels).MetricVec, clock, ttl),
		jitCompiledMethods: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetJITCompiledMethods.Prom,
			Help: "Total methods compiled by the .NET JIT compiler.",
		}, baseLabels).MetricVec, clock, ttl),
		jitCompilationTime: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetJITCompilationTime.Prom,
			Help: "Total .NET JIT compilation time in seconds since the collector baseline.",
		}, baseLabels).MetricVec, clock, ttl),
		threadPoolWorkItemCount: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetThreadPoolWorkItemCount.Prom,
			Help: "Total completed .NET thread-pool work items since the collector baseline.",
		}, baseLabels).MetricVec, clock, ttl),
		monitorLockContentions: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.DotnetMonitorLockContentions.Prom,
			Help: "Total .NET monitor lock contentions since the collector baseline.",
		}, baseLabels).MetricVec, clock, ttl),
		processMemoryWorkingSet: newRuntimeGauge(attributes.DotnetProcessMemoryWorkingSet.Prom,
			"Current physical memory mapped to the .NET process in bytes.", baseLabels, clock, ttl),
		gcCommittedMemory: newRuntimeGauge(attributes.DotnetGCCommittedMemory.Prom,
			"Committed .NET GC memory at the latest collection in bytes.", baseLabels, clock, ttl),
		threadPoolThreadCount: newRuntimeGauge(attributes.DotnetThreadPoolThreadCount.Prom,
			"Current number of .NET thread-pool threads.", baseLabels, clock, ttl),
		threadPoolQueueLength: newRuntimeGauge(attributes.DotnetThreadPoolQueueLength.Prom,
			"Current number of queued .NET thread-pool work items.", baseLabels, clock, ttl),
		timerCount: newRuntimeGauge(attributes.DotnetTimerCount.Prom,
			"Current number of active .NET timers.", baseLabels, clock, ttl),
		assemblyCount: newRuntimeGauge(attributes.DotnetAssemblyCount.Prom,
			"Current number of loaded .NET assemblies.", baseLabels, clock, ttl),
		baseLabelIndexes: baseLabelIndexes,
		clock:            clock,
		ttl:              ttl,
	}
}
