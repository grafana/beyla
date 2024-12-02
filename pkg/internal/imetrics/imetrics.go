// Package imetrics supports recording and submission of internal metrics from Beyla
package imetrics

import (
	"context"
)

// Config options for the different metrics exporters
type Config struct {
	Prometheus  PrometheusConfig `yaml:"prometheus,omitempty"`
	OTELMetrics bool             `yaml:"otel_metrics,omitempty" env:"BEYLA_INTERNAL_OTEL_METRICS"`
}

// Reporter of internal metrics
type Reporter interface {
	// Start the reporter
	Start(ctx context.Context)
	// TracerFlush is invoked every time the eBPF tracer flushes a group of len traces.
	TracerFlush(len int)
	// OTELMetricExport is invoked every time the OpenTelemetry Metrics exporter successfully exports metrics to
	// a remote collector. It accounts the length, in metrics, for each invocation.
	OTELMetricExport(len int)
	// OTELMetricExportError is invoked every time the OpenTelemetry Metrics export fails with an error
	OTELMetricExportError(err error)
	// OTELTraceExport is invoked every time the OpenTelemetry Traces exporter successfully exports traces to
	// a remote collector. It accounts the length, in traces, for each invocation.
	OTELTraceExport(i int)
	// OTELTraceExportError is invoked every time the OpenTelemetry Traces export fails with an error
	OTELTraceExportError(err error)
	// PrometheusRequest is invoked every time the Prometheus exporter is invoked, for a given port and path
	PrometheusRequest(port, path string)
	// InstrumentProcess is invoked every time a new process is instrumented
	InstrumentProcess(processName string)
	// UninstrumentProcess is invoked every time a process is removed from the instrumented processed
	UninstrumentProcess(processName string)
}

// NoopReporter is a metrics Reporter that just does nothing
type NoopReporter struct{}

func (n NoopReporter) Start(_ context.Context)       {}
func (n NoopReporter) TracerFlush(_ int)             {}
func (n NoopReporter) OTELMetricExport(_ int)        {}
func (n NoopReporter) OTELMetricExportError(_ error) {}
func (n NoopReporter) OTELTraceExport(_ int)         {}
func (n NoopReporter) OTELTraceExportError(_ error)  {}
func (n NoopReporter) PrometheusRequest(_, _ string) {}
func (n NoopReporter) InstrumentProcess(_ string)    {}
func (n NoopReporter) UninstrumentProcess(_ string)  {}
