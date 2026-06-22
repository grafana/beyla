// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import "debug/elf"

type Sym struct {
	Name string
	Off  uint64
	Len  uint64
	Prog *elf.Prog
}
