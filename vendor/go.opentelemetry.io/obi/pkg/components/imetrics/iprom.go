// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"context"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/buildinfo"
	"go.opentelemetry.io/obi/pkg/components/connector"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

// pipelineBufferLengths buckets for histogram metrics about the number of traces submitted from one stage to another
// its maximum size will be configuration's batch_length at maximum
// TODO: let users override it or create it from the batch_length value
var pipelineBufferLengths = []float64{0, 10, 20, 40, 80, 160, 320}

type PrometheusConfig struct {
	Port int    `yaml:"port,omitempty" env:"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"OTEL_EBPF_INTERNAL_METRICS_PROMETHEUS_PATH"`
}

// PrometheusReporter is an internal metrics Reporter that exports to Prometheus
type PrometheusReporter struct {
	connector             *connector.PrometheusManager
	tracerFlushes         prometheus.Histogram
	otelMetricExports     prometheus.Counter
	otelMetricExportErrs  *prometheus.CounterVec
	otelTraceExports      prometheus.Counter
	otelTraceExportErrs   *prometheus.CounterVec
	prometheusRequests    *prometheus.CounterVec
	instrumentedProcesses *prometheus.GaugeVec
	instrumentationErrors *prometheus.CounterVec
	avoidedServices       *prometheus.GaugeVec
	buildInfo             prometheus.Gauge
}

func NewPrometheusReporter(cfg *PrometheusConfig, manager *connector.PrometheusManager, registry *prometheus.Registry) *PrometheusReporter {
	pr := &PrometheusReporter{
		connector: manager,
		tracerFlushes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:                            attr.VendorPrefix + "_ebpf_tracer_flushes",
			Help:                            "Length of the groups of traces flushed from the eBPF tracer to the next pipeline stage",
			Buckets:                         pipelineBufferLengths,
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: 1 * time.Hour,
		}),
		otelMetricExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_otel_metric_exports_total",
			Help: "Length of the metric batches submitted to the remote OTEL collector",
		}),
		otelMetricExportErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_otel_metric_export_errors_total",
			Help: "Error count on each failed OTEL metric export",
		}, []string{"error"}),
		otelTraceExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_otel_trace_exports_total",
			Help: "Length of the trace batches submitted to the remote OTEL collector",
		}),
		otelTraceExportErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_otel_trace_export_errors_total",
			Help: "Error count on each failed OTEL trace export",
		}, []string{"error"}),
		prometheusRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_prometheus_http_requests_total",
			Help: "Requests towards the Prometheus Scrape endpoint",
		}, []string{"port", "path"}),
		instrumentedProcesses: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + "_instrumented_processes",
			Help: "Total number of instrumented processes by process name",
		}, []string{"process_name"}),
		instrumentationErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: attr.VendorPrefix + "_instrumentation_errors_total",
			Help: "Total number of instrumentation errors by process name and error type",
		}, []string{"process_name", "error_type"}),
		avoidedServices: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + "_avoided_services",
			Help: "Services avoided due to existing OpenTelemetry instrumentation",
		}, []string{"service_name", "service_namespace", "service_instance_id", "telemetry_type"}),
		buildInfo: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: attr.VendorPrefix + "_internal_build_info",
			Help: "A metric with a constant '1' value labeled by version, revision, branch, " +
				"goversion, goos and goarch during build.",
			ConstLabels: map[string]string{
				"goarch":    runtime.GOARCH,
				"goos":      runtime.GOOS,
				"goversion": runtime.Version(),
				"version":   buildinfo.Version,
				"revision":  buildinfo.Revision,
			},
		}),
	}
	if registry != nil {
		registry.MustRegister(pr.tracerFlushes,
			pr.otelMetricExports,
			pr.otelMetricExportErrs,
			pr.otelTraceExports,
			pr.otelTraceExportErrs,
			pr.prometheusRequests,
			pr.instrumentedProcesses,
			pr.instrumentationErrors,
			pr.avoidedServices,
			pr.buildInfo)
	} else {
		manager.Register(cfg.Port, cfg.Path,
			pr.tracerFlushes,
			pr.otelMetricExports,
			pr.otelMetricExportErrs,
			pr.otelTraceExports,
			pr.otelTraceExportErrs,
			pr.prometheusRequests,
			pr.instrumentedProcesses,
			pr.instrumentationErrors,
			pr.avoidedServices,
			pr.buildInfo)
	}

	return pr
}

func (p *PrometheusReporter) Start(ctx context.Context) {
	if p.connector != nil {
		p.connector.StartHTTP(ctx)
	}
	p.buildInfo.Set(1)
}

func (p *PrometheusReporter) TracerFlush(length int) {
	p.tracerFlushes.Observe(float64(length))
}

func (p *PrometheusReporter) OTELMetricExport(length int) {
	p.otelMetricExports.Add(float64(length))
}

func (p *PrometheusReporter) OTELMetricExportError(err error) {
	p.otelMetricExportErrs.WithLabelValues(err.Error()).Inc()
}

func (p *PrometheusReporter) OTELTraceExport(length int) {
	p.otelTraceExports.Add(float64(length))
}

func (p *PrometheusReporter) OTELTraceExportError(err error) {
	p.otelTraceExportErrs.WithLabelValues(err.Error()).Inc()
}

func (p *PrometheusReporter) PrometheusRequest(port, path string) {
	p.prometheusRequests.WithLabelValues(port, path).Inc()
}

func (p *PrometheusReporter) InstrumentProcess(processName string) {
	p.instrumentedProcesses.WithLabelValues(processName).Inc()
}

func (p *PrometheusReporter) UninstrumentProcess(processName string) {
	p.instrumentedProcesses.WithLabelValues(processName).Dec()
}

func (p *PrometheusReporter) InstrumentationError(processName string, errorType string) {
	p.instrumentationErrors.WithLabelValues(processName, errorType).Inc()
}

func (p *PrometheusReporter) recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, telemetryType string) {
	p.avoidedServices.WithLabelValues(serviceName, serviceNamespace, serviceInstanceID, telemetryType).Set(1)
}

func (p *PrometheusReporter) AvoidInstrumentationMetrics(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "metrics")
}

func (p *PrometheusReporter) AvoidInstrumentationTraces(serviceName, serviceNamespace, serviceInstanceID string) {
	p.recordAvoidedService(serviceName, serviceNamespace, serviceInstanceID, "traces")
}
