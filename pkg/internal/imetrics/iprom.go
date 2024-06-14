package imetrics

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/beyla/pkg/internal/connector"
)

// pipelineBufferLengths buckets for histogram metrics about the number of traces submitted from one stage to another
// its maximum size will be configuration's batch_length at maximum
// TODO: let users override it or create it from the batch_length value
var pipelineBufferLengths = []float64{0, 10, 20, 40, 80, 160, 320}

type PrometheusConfig struct {
	Port int    `yaml:"port,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"BEYLA_INTERNAL_METRICS_PROMETHEUS_PATH"`
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
}

func NewPrometheusReporter(cfg *PrometheusConfig, manager *connector.PrometheusManager) *PrometheusReporter {
	pr := &PrometheusReporter{
		connector: manager,
		tracerFlushes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:                            "ebpf_tracer_flushes",
			Help:                            "length of the groups of traces flushed from the eBPF tracer to the next pipeline stage",
			Buckets:                         pipelineBufferLengths,
			NativeHistogramBucketFactor:     1.1,
			NativeHistogramMaxBucketNumber:  100,
			NativeHistogramMinResetDuration: 1 * time.Hour,
		}),
		otelMetricExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otel_metric_exports",
			Help: "length of the metric batches submitted to the remote OTEL collector",
		}),
		otelMetricExportErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "otel_metric_export_errors",
			Help: "error count on each failed OTEL metric export",
		}, []string{"error"}),
		otelTraceExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otel_trace_exports",
			Help: "length of the trace batches submitted to the remote OTEL collector",
		}),
		otelTraceExportErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "otel_trace_export_errors",
			Help: "error count on each failed OTEL trace export",
		}, []string{"error"}),
		prometheusRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "prometheus_http_requests",
			Help: "requests towards the Prometheus Scrape endpoint",
		}, []string{"port", "path"}),
		instrumentedProcesses: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "beyla_instrumented_processes",
			Help: "instrumented processes by Beyla",
		}, []string{"process_name"}),
	}
	manager.Register(cfg.Port, cfg.Path,
		pr.tracerFlushes,
		pr.otelMetricExports,
		pr.otelMetricExportErrs,
		pr.otelTraceExports,
		pr.otelTraceExportErrs,
		pr.prometheusRequests,
		pr.instrumentedProcesses)

	return pr
}

func (p *PrometheusReporter) Start(ctx context.Context) {
	p.connector.StartHTTP(ctx)
}

func (p *PrometheusReporter) TracerFlush(len int) {
	p.tracerFlushes.Observe(float64(len))
}

func (p *PrometheusReporter) OTELMetricExport(len int) {
	p.otelMetricExports.Add(float64(len))
}

func (p *PrometheusReporter) OTELMetricExportError(err error) {
	p.otelMetricExportErrs.WithLabelValues(err.Error()).Inc()
}

func (p *PrometheusReporter) OTELTraceExport(len int) {
	p.otelTraceExports.Add(float64(len))
}

func (p *PrometheusReporter) OTELTraceExportError(err error) {
	p.otelTraceExportErrs.WithLabelValues(err.Error()).Inc()
}

func (p *PrometheusReporter) PrometheusRequest(port, path string) {
	p.prometheusRequests.WithLabelValues(port, path).Inc()
}

func (p *PrometheusReporter) InstrumentProcess(process_name string) {
	p.instrumentedProcesses.WithLabelValues(process_name).Inc()
}

func (p *PrometheusReporter) UninstrumentProcess(process_name string) {
	p.instrumentedProcesses.WithLabelValues(process_name).Dec()
}
