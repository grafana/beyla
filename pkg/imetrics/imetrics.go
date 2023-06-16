// Package imetrics supports recording and submission of internal metrics from the autoinstrument
package imetrics

import (
	"context"
)

// Config options for the different metrics exporters
type Config struct {
	Prometheus PrometheusConfig `yaml:"prometheus,omitempty"`
}

// Reporter of internal metrics
type Reporter interface {
	// Start the reporter
	Start(ctx context.Context)
	// TracerFlush is invoked every time the eBPF tracer flushes a group of len traces.
	TracerFlush(len int)
}

// NoopReporter is a metrics Reporter that just does nothing
type NoopReporter struct{}

func (n NoopReporter) Start(_ context.Context) {}
func (n NoopReporter) TracerFlush(_ int)       {}
