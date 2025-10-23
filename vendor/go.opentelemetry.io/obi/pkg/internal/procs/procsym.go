// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import "debug/elf"

type Sym struct {
	Off  uint64
	Len  uint64
	Prog *elf.Prog
}
