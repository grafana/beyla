// Package goexec helps analyzing Go executables
package goexec

import (
	"debug/gosym"
	"fmt"

	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/internal/exec"
)

type Offsets struct {
	// Funcs key: function name
	Funcs  map[string]FuncOffsets
	Field  FieldOffsets
	SymTab *gosym.Table
}

type FuncOffsets struct {
	Start   uint64
	Returns []uint64
}

type FieldOffsets map[GoOffset]any

// InspectOffsets gets the memory addresses/offsets of the instrumenting function, as well as the required
// parameters fields to be read from the eBPF code
func InspectOffsets(cfg *otel.TracesConfig, execElf *exec.FileInfo, funcs []string) (*Offsets, error) {
	if execElf == nil {
		return nil, fmt.Errorf("executable not found")
	}

	// Analyse executable ELF file and find instrumentation points
	found, symTab, err := instrumentationPoints(execElf.ELF, funcs)
	if err != nil {
		return nil, fmt.Errorf("finding instrumentation points: %w", err)
	}
	// symTab would be used to find the function name from the address when
	// capturing Go errors. If the option is disabled, whe don't need to keep
	// the symbol table in memory.
	if !cfg.ReportExceptionEvents {
		symTab = nil
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("couldn't find any instrumentation point in %s", execElf.CmdExePath)
	}

	// check the offsets of the required fields from the method arguments
	structFieldOffsets, err := structMemberOffsets(execElf.ELF)
	if err != nil {
		return nil, fmt.Errorf("checking struct members in file %s: %w", execElf.ProExeLinkPath, err)
	}

	return &Offsets{
		Funcs:  found,
		Field:  structFieldOffsets,
		SymTab: symTab,
	}, nil
}
