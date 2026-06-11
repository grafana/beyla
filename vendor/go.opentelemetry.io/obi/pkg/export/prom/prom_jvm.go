// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type jvmRuntimeMetricsReporter struct {
	cfg *PrometheusConfig

	input <-chan []jvmruntime.JVMRuntimeEvent

	memoryUsed            *Expirer[prometheus.Gauge]
	memoryCommitted       *Expirer[prometheus.Gauge]
	memoryLimit           *Expirer[prometheus.Gauge]
	memoryUsedAfterLastGC *Expirer[prometheus.Gauge]
	heapUsed              *Expirer[prometheus.Gauge]

	promConnect connectorPrometheusManager
}

type connectorPrometheusManager interface {
	Register(port int, path string, collectors ...prometheus.Collector)
	StartHTTP(ctx context.Context)
}

func JVMRuntimeMetricsEndpoint(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	input *msg.Queue[[]jvmruntime.JVMRuntimeEvent],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if input == nil || !cfg.EndpointEnabled() || !jointMetricsConfig.Features.AppJVM() {
			return swarm.EmptyRunFunc()
		}
		reporter := newJVMRuntimeMetricsReporter(ctxInfo, cfg, jointMetricsConfig, nil)
		reporter.input = input.Subscribe(msg.SubscriberName("prom.JVMRuntimeMetrics"))
		if cfg.Registry != nil {
			return reporter.collectMetrics, nil
		}
		return reporter.reportMetrics, nil
	}
}

func newJVMRuntimeMetricsReporter(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
	jointMetricsConfig *perapp.MetricsConfig,
	_ any,
) *jvmRuntimeMetricsReporter {
	if !jointMetricsConfig.Features.AppJVM() {
		return &jvmRuntimeMetricsReporter{}
	}

	clock := timeNow
	reporter := &jvmRuntimeMetricsReporter{
		cfg:         cfg,
		promConnect: ctxInfo.Prometheus,
		memoryUsed: newJVMGauge(attributes.JVMMemoryUsed.Prom,
			"Current used JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryCommitted: newJVMGauge(attributes.JVMMemoryCommitted.Prom,
			"Current committed JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryLimit: newJVMGauge(attributes.JVMMemoryLimit.Prom,
			"Current maximum JVM memory in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		memoryUsedAfterLastGC: newJVMGauge(attributes.JVMMemoryUsedAfterLastGC.Prom,
			"JVM memory used after the last garbage collection in bytes.", jvmMemoryLabels(), clock, cfg.TTL),
		heapUsed: newJVMGauge(attributes.BeylaJVMHeapUsed.Prom,
			"HotSpot heap used in bytes as reported by GCTracer::report_gc_heap_summary.", jvmHeapLabels(), clock, cfg.TTL),
	}

	collectors := []prometheus.Collector{
		reporter.memoryUsed,
		reporter.memoryCommitted,
		reporter.memoryLimit,
		reporter.memoryUsedAfterLastGC,
		reporter.heapUsed,
	}
	if cfg.Registry != nil {
		cfg.Registry.MustRegister(collectors...)
	} else if reporter.promConnect != nil {
		reporter.promConnect.Register(cfg.Port, cfg.Path, collectors...)
	}
	return reporter
}

func newJVMGauge(name, help string, labels []string, clock func() time.Time, ttl time.Duration) *Expirer[prometheus.Gauge] {
	return NewExpirer[prometheus.Gauge](prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: name,
		Help: help,
	}, labels).MetricVec, clock, ttl)
}

func (r *jvmRuntimeMetricsReporter) reportMetrics(ctx context.Context) {
	if r.promConnect != nil {
		go r.promConnect.StartHTTP(ctx)
	}
	r.collectMetrics(ctx)
}

func (r *jvmRuntimeMetricsReporter) collectMetrics(ctx context.Context) {
	log := slog.With("component", "prom.JVMRuntimeMetricsReporter")
	swarms.ForEachInput(ctx, r.input, log.Debug, func(events []jvmruntime.JVMRuntimeEvent) {
		for i := range events {
			r.observe(events[i])
		}
	})
}

func (r *jvmRuntimeMetricsReporter) observe(event jvmruntime.JVMRuntimeEvent) {
	if !event.Service.ExportModes.CanExportMetrics() || !event.Service.Features.AppJVM() {
		return
	}

	switch event.Kind {
	case jvmruntime.JVMMetricMemoryUsed:
		r.memoryUsed.WithLabelValues(jvmMemoryLabelValues(event)...).Metric.Set(float64(event.ValueBytes))
	case jvmruntime.JVMMetricMemoryCommitted:
		r.memoryCommitted.WithLabelValues(jvmMemoryLabelValues(event)...).Metric.Set(float64(event.ValueBytes))
	case jvmruntime.JVMMetricMemoryLimit:
		r.memoryLimit.WithLabelValues(jvmMemoryLabelValues(event)...).Metric.Set(float64(event.ValueBytes))
	case jvmruntime.JVMMetricMemoryUsedAfterLastGC:
		r.memoryUsedAfterLastGC.WithLabelValues(jvmMemoryLabelValues(event)...).Metric.Set(float64(event.ValueBytes))
	case jvmruntime.JVMMetricBeylaHeapUsed:
		r.heapUsed.WithLabelValues(jvmHeapLabelValues(event)...).Metric.Set(float64(event.ValueBytes))
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

func jvmServiceLabelValues(event jvmruntime.JVMRuntimeEvent) []string {
	return []string{
		event.Service.UID.Name,
		event.Service.UID.Namespace,
		event.Service.UID.Instance,
	}
}

func jvmMemoryLabelValues(event jvmruntime.JVMRuntimeEvent) []string {
	return append(jvmServiceLabelValues(event), string(event.MemoryType), event.PoolName)
}

func jvmHeapLabelValues(event jvmruntime.JVMRuntimeEvent) []string {
	return append(jvmServiceLabelValues(event), string(event.GCPhase))
}
