// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"
	"io"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

func (pt *ProcessTracer) RegisterNodeSpan(pid app.PID, span *config.CustomSpanSpec, cookie uint64, id string, generation uint64) (io.Closer, error) {
	pt.instrumentablesMu.Lock()
	defer pt.instrumentablesMu.Unlock()
	if pt.stopped {
		return nil, errTracerStopped
	}
	for _, program := range pt.Programs {
		if runtime, ok := program.(interface {
			RegisterNodeSpan(app.PID, *config.CustomSpanSpec, uint64, string, uint64) (io.Closer, error)
		}); ok {
			return runtime.RegisterNodeSpan(pid, span, cookie, id, generation)
		}
	}
	return nil, errors.New("node dynamic span receiver is not loaded")
}
