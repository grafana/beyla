package imetrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/grafana/ebpf-autoinstrument/pkg/connector"
)

// pipelineBufferLengths buckets for histogram metrics about the number of traces submitted from one stage to another
// its maximum size will be configuration's batch_length at maximum
// TODO: let users override it or create it from the batch_length value
var pipelineBufferLengths = []float64{0, 10, 20, 40, 80, 160, 320}

type PrometheusConfig struct {
	Port int    `yaml:"port,omitempty" env:"INTERNAL_METRICS_PROMETHEUS_PORT"`
	Path string `yaml:"path,omitempty" env:"INTERNAL_METRICS_PROMETHEUS_PATH"`
}

// PrometheusReporter is an internal metrics Reporter that exports to Prometheus
type PrometheusReporter struct {
	connector             *connector.PrometheusManager
	tracerFlushes         prometheus.Histogram
	otelMetricExports     prometheus.Counter
	otelMetricsExportErrs *prometheus.CounterVec
}

func NewPrometheusReporter(cfg *PrometheusConfig, manager *connector.PrometheusManager) *PrometheusReporter {
	pr := &PrometheusReporter{
		connector: manager,
		tracerFlushes: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "ebpf_tracer_flushes",
			Help:    "length of the groups of traces flushed from the eBPF tracer to the next pipeline stage",
			Buckets: pipelineBufferLengths,
		}),
		otelMetricExports: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "otel_metric_exports",
			Help: "length of the metric batches submitted to the remote OTEL collector",
		}),
		otelMetricsExportErrs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "otel_metric_export_errors",
			Help: "error count on each failed OTEL metric export",
		}, []string{"error"}),
	}
	manager.Register(cfg.Port, cfg.Path, pr.tracerFlushes)

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
	p.otelMetricsExportErrs.WithLabelValues(err.Error()).Inc()
}
