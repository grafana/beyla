// Package imetrics supports recording and submission of internal metrics from the autoinstrument
package imetrics

type Reporter interface {
	TracerFlush(len int)
}

type NoopReporter struct{}

func (n NoopReporter) TracerFlush(_ int) {}
