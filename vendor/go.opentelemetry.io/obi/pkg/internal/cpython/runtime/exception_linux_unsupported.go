// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64

package runtime // import "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"

import (
	"debug/elf"
	"fmt"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// deriveErrSetObject fails closed: hidden-symbol derivation supports amd64 only.
func deriveErrSetObject(*elf.File, procs.Sym, []procs.Sym) (uint64, error) {
	return 0, fmt.Errorf("%w: deriving _PyErr_SetObject requires amd64", errUnsupportedLayout)
}
