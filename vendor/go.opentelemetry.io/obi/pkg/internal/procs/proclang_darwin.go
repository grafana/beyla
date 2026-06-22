// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"debug/elf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func FindProcLanguage(_ app.PID) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File, _ []string, _ ...elf.SymType) (map[string]Sym, error) {
	return nil, nil
}

func FindExeSymbolsBySubstring(_ *elf.File, _ []string, _ ...elf.SymType) (map[string]Sym, error) {
	return nil, nil
}

func FindExeSymbolsByNameAndSubstring(_ *elf.File, _, _ []string, _ ...elf.SymType) (map[string]Sym, map[string]Sym, error) {
	return nil, nil, nil
}
