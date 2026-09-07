// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"fmt"

	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
)

// findPythonGCDoneUSDT finds one python:gc__done marker in SystemTap notes.
func findPythonGCDoneUSDT(file *elf.File) (*GCCompletionProbe, error) {
	// CPython documents this marker at https://docs.python.org/3/howto/instrumentation.html#available-static-markers.
	targets, err := obiebpf.FindUSDTProbeTargets(file, "python", "gc__done")
	if err != nil {
		return nil, fmt.Errorf("%w: invalid python:gc__done USDT probe: %w", errUnsupportedLayout, err)
	}
	switch len(targets) {
	case 0:
		return nil, nil
	case 1:
		target := targets[0]
		return &GCCompletionProbe{
			Kind:            GCCompletionProbeUSDT,
			FileOffset:      target.FileOffset,
			SemaphoreOffset: target.SemaphoreOffset,
		}, nil
	default:
		return nil, fmt.Errorf("%w: ambiguous python:gc__done USDT notes", errUnsupportedLayout)
	}
}
