// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"slices"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	nodejsruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

type nodejsRuntimeMetricsCollector struct {
	eventLoopTime        *Expirer[prometheus.Counter]
	eventLoopUtilization *Expirer[prometheus.Gauge]
	delayMin             *Expirer[prometheus.Gauge]
	delayMax             *Expirer[prometheus.Gauge]
	delayMean            *Expirer[prometheus.Gauge]
	delayStddev          *Expirer[prometheus.Gauge]
	delayP50             *Expirer[prometheus.Gauge]
	delayP90             *Expirer[prometheus.Gauge]
	delayP99             *Expirer[prometheus.Gauge]

	gcDuration    *Expirer[prometheus.Histogram]
	heapLimit     *Expirer[prometheus.Gauge]
	heapUsed      *Expirer[prometheus.Gauge]
	heapAvailable *Expirer[prometheus.Gauge]
	heapPhysical  *Expirer[prometheus.Gauge]

	// cumulative ELU values tracked per Instance|PID to compute counter
	// deltas; TTL-expired so process churn cannot grow it without bound
	prev           *expire.ExpiryMap[*nodejsPrevELU]
	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

type nodejsPrevELU struct {
	idleNs      uint64
	activeNs    uint64
	initialized bool
}

func newNodejsRuntimeMetricsCollector(cfg *PrometheusConfig) nodejsRuntimeMetricsCollector {
	clock := timeNow
	stateLabels := append(runtimeServiceLabels(), "nodejs_eventloop_state")
	gcLabels := append(runtimeServiceLabels(), attr.V8JSGCType.Prom())
	heapLabels := append(runtimeServiceLabels(), attr.V8JSHeapSpaceName.Prom())
	newGauge := func(name attributes.Name, help string) *Expirer[prometheus.Gauge] {
		return newRuntimeGauge(name.Prom, help, runtimeServiceLabels(), clock, cfg.TTL)
	}

	return nodejsRuntimeMetricsCollector{
		eventLoopTime: NewExpirer[prometheus.Counter](prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attributes.NodejsEventLoopTime.Prom,
			Help: "Cumulative time the nodejs event loop has been active or idle.",
		}, stateLabels).MetricVec, clock, cfg.TTL),
		eventLoopUtilization: newGauge(attributes.NodejsEventLoopUtilization,
			"Ratio of time the nodejs event loop was active over the last sampling interval."),
		delayMin: newGauge(attributes.NodejsEventLoopDelayMin,
			"Minimum nodejs event loop delay over the last sampling interval."),
		delayMax: newGauge(attributes.NodejsEventLoopDelayMax,
			"Maximum nodejs event loop delay over the last sampling interval."),
		delayMean: newGauge(attributes.NodejsEventLoopDelayMean,
			"Mean nodejs event loop delay over the last sampling interval."),
		delayStddev: newGauge(attributes.NodejsEventLoopDelayStddev,
			"Standard deviation of the nodejs event loop delay over the last sampling interval."),
		delayP50: newGauge(attributes.NodejsEventLoopDelayP50,
			"50th percentile of the nodejs event loop delay over the last sampling interval."),
		delayP90: newGauge(attributes.NodejsEventLoopDelayP90,
			"90th percentile of the nodejs event loop delay over the last sampling interval."),
		delayP99: newGauge(attributes.NodejsEventLoopDelayP99,
			"99th percentile of the nodejs event loop delay over the last sampling interval."),
		gcDuration: NewExpirer[prometheus.Histogram](prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    attributes.V8JSGCDuration.Prom,
			Help:    "Duration of V8 garbage collection cycles.",
			Buckets: cfg.Buckets.V8JSGCDurationHistogram,
		}, gcLabels).MetricVec, clock, cfg.TTL),
		heapLimit: newRuntimeGauge(attributes.V8JSMemoryHeapLimit.Prom,
			"Total V8 heap memory size pre-allocated, per heap space.", heapLabels, clock, cfg.TTL),
		heapUsed: newRuntimeGauge(attributes.V8JSMemoryHeapUsed.Prom,
			"V8 heap memory size allocated, per heap space.", heapLabels, clock, cfg.TTL),
		heapAvailable: newRuntimeGauge(attributes.V8JSMemoryHeapSpaceAvailableSize.Prom,
			"V8 heap space available size.", heapLabels, clock, cfg.TTL),
		heapPhysical: newRuntimeGauge(attributes.V8JSMemoryHeapSpacePhysicalSize.Prom,
			"Committed size of a V8 heap space.", heapLabels, clock, cfg.TTL),
		prev:           expire.NewExpiryMap[*nodejsPrevELU](clock, cfg.TTL),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            cfg.TTL,
	}
}

func (c *nodejsRuntimeMetricsCollector) collectors() []prometheus.Collector {
	if c.eventLoopTime == nil {
		return nil
	}
	return []prometheus.Collector{
		c.eventLoopTime,
		c.eventLoopUtilization,
		c.delayMin,
		c.delayMax,
		c.delayMean,
		c.delayStddev,
		c.delayP50,
		c.delayP90,
		c.delayP99,
		c.gcDuration,
		c.heapLimit,
		c.heapUsed,
		c.heapAvailable,
		c.heapPhysical,
	}
}

// collectNodejsV8Metrics handles the v8js snapshot variants: the gc duration
// histogram (one observation per collection cycle) and the per-space heap
// gauges (absolute sample values, like the JVM memory gauges).
func (r *metricsReporter) collectNodejsV8Metrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	c := &r.nodejsRuntimeMetrics
	if c.gcDuration == nil ||
		!snapshot.Service.ExportModes.CanExportMetrics() ||
		!snapshot.Service.Features.AppRuntime() {
		return
	}

	const nanosPerSecond = 1e9

	serviceLabels := runtimeServiceLabelValues(snapshot)

	if gc := snapshot.NodejsGC; gc != nil && gc.GCType != nodejsruntime.NodejsGCTypeUnknown {
		c.gcDuration.WithLabelValues(slices.Concat(serviceLabels, []string{gc.GCType.String()})...).
			Metric.Observe(float64(gc.DurationNs) / nanosPerSecond)
	}

	if heap := snapshot.NodejsHeapSpace; heap != nil {
		labels := slices.Concat(serviceLabels, []string{heap.SpaceName})
		c.heapLimit.WithLabelValues(labels...).Metric.Set(float64(heap.SpaceSize))
		c.heapUsed.WithLabelValues(labels...).Metric.Set(float64(heap.SpaceUsedSize))
		c.heapAvailable.WithLabelValues(labels...).Metric.Set(float64(heap.SpaceAvailableSize))
		c.heapPhysical.WithLabelValues(labels...).Metric.Set(float64(heap.PhysicalSpaceSize))
	}
}

func (r *metricsReporter) collectNodejsRuntimeMetrics(snapshot runtimemetrics.RuntimeMetricSnapshot) {
	c := &r.nodejsRuntimeMetrics
	if c.eventLoopTime == nil ||
		snapshot.Nodejs == nil ||
		!snapshot.Service.ExportModes.CanExportMetrics() ||
		!snapshot.Service.Features.AppRuntime() {
		return
	}

	const nanosPerSecond = 1e9

	values := snapshot.Nodejs.NodejsEventLoopValues
	serviceLabels := runtimeServiceLabelValues(snapshot)

	// keyed by the host-visible pid: namespace-local pids can collide
	// (full rationale in otel/metrics_nodejs.go)
	idleDelta, activeDelta := c.eluDeltas(
		snapshot.Service.UID.Instance+"|"+strconv.Itoa(int(snapshot.Service.ProcPID)),
		values.ELUIdleNs,
		values.ELUActiveNs,
	)
	// Expirer keeps the slice it is given and later feeds it back to
	// DeleteLabelValues, so the two state label sets must not share an array.
	if idleDelta > 0 {
		c.eventLoopTime.WithLabelValues(slices.Concat(serviceLabels, []string{"idle"})...).
			Metric.Add(float64(idleDelta) / nanosPerSecond)
	}
	if activeDelta > 0 {
		c.eventLoopTime.WithLabelValues(slices.Concat(serviceLabels, []string{"active"})...).
			Metric.Add(float64(activeDelta) / nanosPerSecond)
	}
	if total := idleDelta + activeDelta; total > 0 {
		c.eventLoopUtilization.WithLabelValues(serviceLabels...).
			Metric.Set(float64(activeDelta) / float64(total))
	}

	// no delay samples (fully blocked interval): keep the previous window's
	// values (full rationale in otel/metrics_nodejs.go); the Expirer retires
	// them if the process stays silent
	if values.DelayCount == 0 {
		return
	}
	c.delayMin.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayMinNs) / nanosPerSecond)
	c.delayMax.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayMaxNs) / nanosPerSecond)
	c.delayMean.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayMeanNs) / nanosPerSecond)
	c.delayStddev.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayStddevNs) / nanosPerSecond)
	c.delayP50.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayP50Ns) / nanosPerSecond)
	c.delayP90.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayP90Ns) / nanosPerSecond)
	c.delayP99.WithLabelValues(serviceLabels...).Metric.Set(float64(values.DelayP99Ns) / nanosPerSecond)
}

func (c *nodejsRuntimeMetricsCollector) eluDeltas(key string, idleNs, activeNs uint64) (uint64, uint64) {
	if now := c.clock(); now.Sub(c.lastExpiration) >= c.ttl {
		c.prev.DeleteExpired()
		c.lastExpiration = now
	}

	prev := c.prev.GetOrCreate([]string{key}, func() *nodejsPrevELU {
		return &nodejsPrevELU{}
	})

	idleDelta := runtimemetrics.NodejsCounterDelta(prev.initialized, prev.idleNs, idleNs)
	activeDelta := runtimemetrics.NodejsCounterDelta(prev.initialized, prev.activeNs, activeNs)
	prev.idleNs = idleNs
	prev.activeNs = activeNs
	prev.initialized = true
	return idleDelta, activeDelta
}
