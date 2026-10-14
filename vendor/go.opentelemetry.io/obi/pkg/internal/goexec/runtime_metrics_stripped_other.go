// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !amd64

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"debug/elf"
	"debug/gosym"
)

// resolveGOMAXPROCSFromCode reports that instruction-based global recovery is
// unsupported on this architecture. Symbol-based resolution uses a separate path.
func resolveGOMAXPROCSFromCode(_ *elf.File, _ uint64, _ []byte) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}

// resolveRuntimeMetricReceiverFromCode reports that receiver recovery requires
// the amd64 instruction matcher.
func resolveRuntimeMetricReceiverFromCode(_ uint64, _ []byte, _ ...uint64) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}

// resolveRuntimeMetricSizeClassTableFromCode requires the amd64 instruction matcher.
func resolveRuntimeMetricSizeClassTableFromCode(_ *elf.File, _ *gosym.Table) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}

// resolveRuntimeMetricSchedGoIDFromCode requires the amd64 atomic-update matcher.
func resolveRuntimeMetricSchedGoIDFromCode(_ *elf.File, _ uint64, _ []byte) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}

// resolveRuntimeMetricAllgLenFromCode requires the amd64 atomic-store matcher.
func resolveRuntimeMetricAllgLenFromCode(_ *elf.File, _ uint64, _ []byte) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}

// resolveRuntimeMetricAllpFromCode requires the amd64 slice-loop matcher.
func resolveRuntimeMetricAllpFromCode(_ *elf.File, _ uint64, _ []byte) (uint64, error) {
	return 0, ErrUnsupportedArchitecture
}
