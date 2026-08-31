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

// strictELFFileOffset maps one virtual address to exactly one file-backed load segment.
func strictELFFileOffset(file *elf.File, address uint64, executable bool) (uint64, error) {
	var offset uint64
	matches := 0
	for _, program := range file.Progs {
		// Require a file-backed load segment. Probe locations must also belong to
		// an executable segment, while semaphore locations can belong to data.
		if program.Type != elf.PT_LOAD || executable && program.Flags&elf.PF_X == 0 ||
			address < program.Vaddr || address-program.Vaddr >= program.Filesz {
			continue
		}
		candidate := program.Off + address - program.Vaddr
		if candidate < program.Off || candidate == 0 {
			return 0, fmt.Errorf("%w: invalid CPython probe file offset", errUnsupportedLayout)
		}
		offset = candidate
		matches++
	}
	if matches != 1 {
		return 0, fmt.Errorf("%w: CPython probe address maps to %d file segments", errUnsupportedLayout, matches)
	}
	return offset, nil
}
