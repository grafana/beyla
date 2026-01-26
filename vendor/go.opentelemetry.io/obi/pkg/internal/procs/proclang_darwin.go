// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs

import (
	"debug/elf"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
)

func FindProcLanguage(_ int32) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File, _ []string) (map[string]Sym, error) {
	return nil, nil
}
